package vpn

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/workeripc"
)

type probeOriginalDialer struct{ calls int }

func (d *probeOriginalDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls++
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func TestEasyConnectBusinessProbeNeverUsesOrdinaryFallback(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			dialer := &probeOriginalDialer{}
			s := &processSession{
				dialer: dialer,
				done:   make(chan struct{}), stopping: make(chan struct{}),
				info: SessionInfo{Resources: &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{
					{Min: "10.1.2.3", Max: "10.1.2.3", PortMin: 3306, PortMax: 3306, Protocol: protocol},
				}}},
			}
			err := s.Probe(context.Background())
			want := ErrStrictVPNUnavailable
			if protocol == "udp" {
				want = errProbeUnavailable
			}
			if !errors.Is(err, want) || dialer.calls != 0 {
				t.Fatalf("Probe()=%v, ordinary dials=%d; want %v without original-network dialing", err, dialer.calls, want)
			}
		})
	}
}

type probeDNSSuccessSession struct {
	*fakeSession
	dnsCalls, strictCalls int
	strictErr             error
	dnsErr                error
}

func (s *probeDNSSuccessSession) Probe(ctx context.Context) error {
	return s.ProbeDNS(ctx)
}

func (s *probeDNSSuccessSession) ProbeDNS(context.Context) error {
	s.dnsCalls++
	return s.dnsErr
}

func (s *probeDNSSuccessSession) DialVPN(context.Context, string, string) (net.Conn, error) {
	s.strictCalls++
	if s.strictErr != nil {
		return nil, s.strictErr
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func TestBusinessProbeDoesNotSubstituteSuccessfulDNS(t *testing.T) {
	closedPort := errors.New("authorized business port is closed")
	s := &probeDNSSuccessSession{fakeSession: newFakeSession("A"), strictErr: closedPort}
	err := probeSession(context.Background(), s, "10.1.2.3:3306")
	if !errors.Is(err, closedPort) || s.strictCalls != 1 || s.dnsCalls != 0 {
		t.Fatalf("business probe=%v, strict=%d DNS=%d; expected the actual VPN TCP result", err, s.strictCalls, s.dnsCalls)
	}
}

func TestHealthChecksKeepDNSAndBusinessResultsSeparate(t *testing.T) {
	closedPort := errors.New("business port closed")
	brokenDNS := errors.New("gateway DNS unavailable")
	for _, test := range []struct {
		name, target, dnsState, tcpState string
		dnsErr, tcpErr, wantErr          error
	}{
		{name: "DNS cannot erase business failure", target: "10.1.2.3:3306", dnsState: "ok", tcpState: "failed", tcpErr: closedPort},
		{name: "business cannot erase DNS failure", target: "10.1.2.3:3306", dnsState: "failed", tcpState: "ok", dnsErr: brokenDNS},
		{name: "both failed", target: "10.1.2.3:3306", dnsState: "failed", tcpState: "failed", dnsErr: brokenDNS, tcpErr: closedPort, wantErr: closedPort},
		{name: "no business target", dnsState: "ok"},
		{name: "nothing to verify", dnsErr: errProbeUnavailable, wantErr: errProbeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &probeDNSSuccessSession{fakeSession: newFakeSession("A"), strictErr: test.tcpErr, dnsErr: test.dnsErr}
			dnsResult, tcpResult, err := sessionHealth(context.Background(), s, test.target)
			if !errors.Is(err, test.wantErr) || dnsResult.State != test.dnsState || tcpResult.State != test.tcpState {
				t.Fatalf("DNS=%+v TCP=%+v err=%v", dnsResult, tcpResult, err)
			}
			if test.target == "" && (tcpResult != (ProbeResult{}) || s.strictCalls != 0) {
				t.Fatal("no target was reported as a verified business", tcpResult)
			}
			if test.tcpState == "failed" && (tcpResult.Target != test.target || tcpResult.Error != test.tcpErr.Error() || tcpResult.CheckedAt == 0) {
				t.Fatal("business evidence was lost", tcpResult)
			}
			if len(s.dials) != 0 {
				t.Fatal("health check used ordinary dialing", s.dials)
			}
		})
	}
}

func TestManagerPublishesHealthOnlyForCurrentSession(t *testing.T) {
	closedPort := errors.New("business port closed")
	s := &probeDNSSuccessSession{fakeSession: newFakeSession("A"), strictErr: closedPort}
	s.info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{
		{Min: "10.1.2.3", Max: "10.1.2.3", PortMin: 3306, PortMax: 3306, Protocol: "tcp"},
	}}
	m := newTestManager(t, func(context.Context, model.AccessPoint, Credentials) (Session, error) { return s, nil },
		testConfig(model.AccessPoint{ID: "A", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true}))
	m.Connect("A")
	waitFor(t, "online", func() bool { v, _ := m.View("A"); return v.State == StateOnline })
	m.mu.Lock()
	m.points["A"].lastTraffic = time.Time{}
	gen := m.points["A"].gen
	m.mu.Unlock()
	probeNow(m, "A")
	v, _ := m.View("A")
	if v.DNSProbe.State != "ok" || v.TCPProbe.State != "failed" || v.TCPProbe.Target != "10.1.2.3:3306" || v.TunnelFails != 0 || v.State != StateOnline {
		t.Fatalf("DNS success hid the closed business port or forced a needless reconnect: %+v", v)
	}
	m.recordHealth("A", gen-1, s, ProbeResult{}, ProbeResult{})
	after, _ := m.View("A")
	if after.DNSProbe != v.DNSProbe || after.TCPProbe != v.TCPProbe {
		t.Fatal("old generation overwrote current health")
	}
	m.recordHealth("A", gen, newFakeSession("other"), ProbeResult{}, ProbeResult{})
	after, _ = m.View("A")
	if after.DNSProbe != v.DNSProbe || after.TCPProbe != v.TCPProbe {
		t.Fatal("old session overwrote current health")
	}
	m.Disconnect("A")
	after, _ = m.View("A")
	if after.DNSProbe != (ProbeResult{}) || after.TCPProbe != (ProbeResult{}) {
		t.Fatal("disconnected session retained health evidence")
	}
}

func TestHealthTargetUsesOnlyConcreteIPv4TCPResources(t *testing.T) {
	info := SessionInfo{Apps: []App{{Addresses: []AppAddress{{Protocol: "udp", Host: "10.1.2.3", Port: "53"}}}}}
	if target := healthTarget(info); target != "" {
		t.Fatal("UDP application selected for TCP probe", target)
	}
	info.Apps[0].Addresses[0] = AppAddress{Protocol: "tcp", Host: "10.1.2.3", Port: "443"}
	if target := healthTarget(info); target != "" {
		t.Fatal("display-only app data authorized a probe", target)
	}
	info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{
		{Min: "10.1.2.3", Max: "10.1.2.3", PortMin: 53, PortMax: 53, Protocol: "udp"},
		{Min: "2001:db8::1", Max: "2001:db8::1", PortMin: 443, PortMax: 443, Protocol: "tcp"},
		{Min: "10.1.2.3", Max: "10.1.2.3", PortMin: 1, PortMax: 65535, Protocol: "tcp"},
		{Min: "10.1.2.3", Max: "10.1.2.4", PortMin: 443, PortMax: 443, Protocol: "tcp"},
	}}
	if target := healthTarget(info); target != "" {
		t.Fatal("unsupported or ambiguous resource selected", target)
	}
	info.Resources.IPRules = append(info.Resources.IPRules, workeripc.IPRule{Min: "10.1.2.9", Max: "10.1.2.9", PortMin: 8443, PortMax: 8443, Protocol: "all"})
	if target := healthTarget(info); target != "10.1.2.9:8443" {
		t.Fatal("current TCP resource ignored", target)
	}
	info.HealthTarget = "10.1.2.10:443"
	if target := healthTarget(info); target != "10.1.2.9:8443" {
		t.Fatal("unauthorized configured target accepted", target)
	}
	info.Resources.IPRules = append(info.Resources.IPRules, workeripc.IPRule{Min: "10.1.2.10", Max: "10.1.2.10", PortMin: 443, PortMax: 443, Protocol: "tcp"})
	if target := healthTarget(info); target != info.HealthTarget {
		t.Fatal("authorized configured target ignored", target)
	}
	info.HealthTarget = "db.corp.test:3306"
	if target := healthTarget(info); target != "10.1.2.9:8443" {
		t.Fatal("unauthorized configured domain target accepted", target)
	}
	info.Resources.DomainRules = []workeripc.DomainRule{{Domain: "db.corp.test", PortMin: 3306, PortMax: 3306, Protocol: "tcp"}}
	if target := healthTarget(info); target != info.HealthTarget {
		t.Fatal("authorized domain target ignored", target)
	}
	info.HealthTarget = "2001:db8::1:443"
	if target := healthTarget(info); target != "10.1.2.9:8443" {
		t.Fatal("invalid or IPv6 target accepted", target)
	}
	info.HealthTarget = ""
	info.Resources.IPRules = nil
	info.Resources.DomainRules = []workeripc.DomainRule{
		{Domain: "*.corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"},
		{Domain: "db.corp.test", PortMin: 3306, PortMax: 3306, Protocol: "tcp"},
	}
	if target := healthTarget(info); target != "db.corp.test:3306" {
		t.Fatal("current exact TCP domain resource ignored", target)
	}
	info.Resources.DomainRules = []workeripc.DomainRule{{Domain: "*.corp.test", PortMin: 443, PortMax: 443, Protocol: "tcp"}}
	if target := healthTarget(info); target != "" {
		t.Fatal("wildcard domain selected as probe target", target)
	}
}
