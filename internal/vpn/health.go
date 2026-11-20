package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/routing"
	"github.com/qy/easyconnect/internal/workeripc"
)

// ProbeResult describes one actual check in the current session. An empty
// state means unverified, not success. TCP success only proves establishment.
type ProbeResult struct {
	State     string
	Target    string
	Error     string
	CheckedAt int64
}

// DNSProber checks only this session's remote DNS, never a business port.
type DNSProber interface {
	ProbeDNS(context.Context) error
}

func healthTarget(info SessionInfo) string {
	if host, port, err := net.SplitHostPort(info.HealthTarget); err == nil {
		if target := healthHostPort(host, port); target != "" && authorizedHealthTarget(target, info.Resources) {
			return target
		}
	}
	if info.Resources == nil {
		return ""
	}
	for _, r := range info.Resources.IPRules {
		ip := net.ParseIP(r.Min)
		if r.Min == r.Max && ip != nil && ip.To4() != nil && r.PortMin == r.PortMax && r.PortMin > 0 && r.PortMax <= 65535 && (r.Protocol == "tcp" || r.Protocol == "all") {
			return net.JoinHostPort(ip.String(), strconv.Itoa(r.PortMin))
		}
	}
	for _, r := range info.Resources.DomainRules {
		if r.Protocol != "tcp" && r.Protocol != "all" || r.PortMin != r.PortMax {
			continue
		}
		host := strings.TrimSpace(r.Domain)
		if strings.HasPrefix(host, "*.") || strings.HasPrefix(host, ".") {
			continue
		}
		if target := healthHostPort(strings.TrimSuffix(host, "."), strconv.Itoa(r.PortMin)); target != "" && authorizedHealthTarget(target, info.Resources) {
			return target
		}
	}
	return ""
}

func authorizedHealthTarget(target string, resources *workeripc.ResourceSnapshot) bool {
	if resources == nil {
		return false
	}
	decision := routing.Decide(routing.Request{Network: "tcp", Address: target}, []routing.Gateway{{
		ID: "health-probe", Name: "health-probe", Online: true, Strict: true, Current: resources,
	}}, nil)
	return decision.Action == "vpn" && len(decision.Candidates) == 1 && decision.Candidates[0].ID == "health-probe"
}

func healthHostPort(host, port string) string {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strings.ContainsAny(host, "/\\@* 	\r\n") {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return ""
		}
		return net.JoinHostPort(ip.String(), strconv.Itoa(n))
	}
	host, err = routing.NormalizeHost(host)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(n))
}

func checkedProbe(target string, err error) ProbeResult {
	if errors.Is(err, errProbeUnavailable) {
		return ProbeResult{}
	}
	r := ProbeResult{State: "ok", Target: target, CheckedAt: time.Now().UnixMilli()}
	if err != nil {
		r.State, r.Error = "failed", err.Error()
	}
	return r
}

func safeProbeDNS(ctx context.Context, prober DNSProber) (err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("隧道 DNS 探测失败：%v", value)
		}
	}()
	return prober.ProbeDNS(ctx)
}

func sessionHealth(ctx context.Context, sess Session, target string) (dnsResult, tcpResult ProbeResult, tunnelErr error) {
	// Concurrent checks share one overall deadline, so a slow DNS query does
	// not serialize and consume the time reserved for the business connection.
	// Sessions already support concurrent IPC requests.
	var wg sync.WaitGroup
	var dnsErr, tcpErr error = errProbeUnavailable, errProbeUnavailable
	if prober, ok := sess.(DNSProber); ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnsErr = safeProbeDNS(ctx, prober)
			dnsResult = checkedProbe("网关 DNS", dnsErr)
		}()
	}
	if target != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tcpErr = probeSession(ctx, sess, target)
			tcpResult = checkedProbe(target, tcpErr)
		}()
	}
	wg.Wait()
	// Either successful path proves some tunnel connectivity. A failed business
	// port stays failed in tcpResult even when DNS prevents an unnecessary login.
	if dnsErr == nil || tcpErr == nil {
		return dnsResult, tcpResult, nil
	}
	if !errors.Is(tcpErr, errProbeUnavailable) {
		return dnsResult, tcpResult, tcpErr
	}
	return dnsResult, tcpResult, dnsErr
}

func (m *Manager) recordHealth(id string, gen int, sess Session, dnsResult, tcpResult ProbeResult) {
	m.mu.Lock()
	ep := m.points[id]
	changed := ep != nil && ep.gen == gen && ep.sess == sess && ep.state == StateOnline &&
		(ep.dnsHealth != dnsResult || ep.tcpHealth != tcpResult)
	if changed {
		ep.dnsHealth, ep.tcpHealth = dnsResult, tcpResult
	}
	m.mu.Unlock()
	if changed {
		m.changed()
	}
}
