package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
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

// parseHealthTarget 解析用户填写的保活目标（支持 http(s):// URL 或 host:port 格式）。
func parseHealthTarget(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("目标为空")
	}
	if strings.Contains(raw, "://") {
		if u, parseErr := url.Parse(raw); parseErr == nil {
			h := u.Hostname()
			p := u.Port()
			if p == "" {
				if strings.EqualFold(u.Scheme, "https") {
					p = "443"
				} else {
					p = "80"
				}
			}
			return h, p, nil
		}
	}
	if h, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		return h, p, nil
	}
	return "", "", fmt.Errorf("无效的目标格式：%s", raw)
}

func healthTarget(info SessionInfo, preferred ...string) string {
	// 1. 用户显式配置的保活目标/URL 优先级最高
	if info.HealthTarget != "" {
		if h, p, err := parseHealthTarget(info.HealthTarget); err == nil {
			if target := healthHostPort(h, p); target != "" {
				if info.Resources == nil || authorizedHealthTarget(target, info.Resources) {
					return target
				}
			}
		}
	}
	// 2. 运行时最近一次成功通流的业务目标
	for _, p := range preferred {
		if p == "" {
			continue
		}
		if h, port, err := parseHealthTarget(p); err == nil {
			if target := healthHostPort(h, port); target != "" && authorizedHealthTarget(target, info.Resources) {
				return target
			}
		}
	}
	// 3. 降级：未配置时按原逻辑从网关下发的资源规则中自动挑选
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

// isRemoteTargetError 检查错误是否属于远端单点目标主机不可达、被防火墙拒绝或端口未开启等。
// 这类错误表明本地到网关代理/隧道的通道是畅通的（SOCKS5 握手成功），仅仅是具体业务目标不通，不能当作底层隧道崩溃。
func isRemoteTargetError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "host unreachable") ||
		strings.Contains(msg, "network unreachable") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "target unreachable")
}
