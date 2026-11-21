package vpn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func tunnelApps() []App {
	return []App{{
		ID:   "app-1",
		Name: "内部数据库",
		Addresses: []AppAddress{
			{Protocol: "tcp", Host: "10.1.2.3", Port: "3306"},
		},
	}}
}

// probeNow clears the probe throttle so a test can run several rounds back to
// back.
func probeNow(m *Manager, id string) {
	m.mu.Lock()
	if ep := m.points[id]; ep != nil {
		ep.lastProbe = time.Time{}
	}
	m.mu.Unlock()
	m.probeAll(true)
}

func TestIdleProbeSkipsRecentlyUsedTunnel(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	cfg.Settings.HealthIntervalSec = 60
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	sess := conn.session("a")
	m.mu.Lock()
	m.points["a"].info.Apps = tunnelApps()
	m.mu.Unlock()

	// A tunnel that just carried traffic must not be probed.
	m.noteTraffic("a")
	m.probeAll(true)

	sess.mu.Lock()
	dials := len(sess.dials)
	sess.mu.Unlock()
	if dials != 0 {
		t.Fatalf("probe dialed a busy tunnel %d times", dials)
	}
	if v, _ := m.View("a"); v.TunnelState != "" {
		t.Errorf("tunnel state = %q, want empty", v.TunnelState)
	}
}

func TestIdleProbeMarksDeadTunnelAndSchedulesRebuild(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	cfg.Settings.HealthIntervalSec = 60
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	sess := conn.session("a")
	sess.dialErr = errors.New("tunnel closed by server")

	// connect() stamps lastTraffic; clear it so the tunnel counts as idle.
	m.mu.Lock()
	m.points["a"].info.Apps = tunnelApps()
	m.points["a"].info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.1.2.3", Max: "10.1.2.3", PortMin: 3306, PortMax: 3306, Protocol: "tcp"}}}
	m.points["a"].lastTraffic = time.Time{}
	m.mu.Unlock()

	probeNow(m, "a")
	v, _ := m.View("a")
	if v.TunnelState != "degraded" || v.TunnelFails != 1 {
		t.Fatalf("after one failure: state=%q fails=%d, want degraded/1", v.TunnelState, v.TunnelFails)
	}
	if v.State != StateOnline {
		t.Fatalf("state = %v, want still online after first failure", v.State)
	}

	probeNow(m, "a")
	probeNow(m, "a")
	v, _ = m.View("a")
	if v.State != StateError || v.TunnelState != "dead" {
		t.Fatalf("after three failures: state=%v tunnel=%q, want error/dead", v.State, v.TunnelState)
	}
	if !strings.Contains(v.Error, "隧道已失效") {
		t.Errorf("error = %q, want it to say the tunnel died while the login stays valid", v.Error)
	}
	m.mu.Lock()
	step := m.points["a"].retryStep
	m.mu.Unlock()
	if step == 0 {
		t.Error("no automatic rebuild was scheduled")
	}
}

type unprobeableSession struct {
	*fakeSession
}

func (u unprobeableSession) Probe(context.Context) error { return errProbeUnavailable }

func TestUnprobeableTunnelIsNotAFailure(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	// No application address and no remote DNS: nothing to probe through.
	m.mu.Lock()
	m.points["a"].sess = unprobeableSession{m.points["a"].sess.(*fakeSession)}
	m.points["a"].lastTraffic = time.Time{}
	m.mu.Unlock()

	m.probeAll(true)
	v, _ := m.View("a")
	if v.TunnelState != "" || v.TunnelFails != 0 {
		t.Fatalf("tunnel state = %q fails = %d, want untouched", v.TunnelState, v.TunnelFails)
	}
	if v.State != StateOnline {
		t.Fatalf("state = %v, want online", v.State)
	}
}

func TestStaleProbeDoesNotPolluteNewSession(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})

	m.mu.Lock()
	curGen := m.points["a"].gen
	curSess := m.points["a"].sess
	m.mu.Unlock()

	// 1. Old probe with error must be ignored by current session
	staleGen := curGen - 1
	staleSess := &fakeSession{}
	m.recordProbe("a", "A", staleGen, staleSess, errors.New("old probe failure"), true)

	v, _ := m.View("a")
	if v.TunnelState != "" || v.TunnelFails != 0 {
		t.Fatalf("stale failure polluted current session: state=%q, fails=%d", v.TunnelState, v.TunnelFails)
	}

	// 2. Set current session fails to 2
	m.recordProbe("a", "A", curGen, curSess, errors.New("real failure 1"), true)
	m.recordProbe("a", "A", curGen, curSess, errors.New("real failure 2"), true)
	v, _ = m.View("a")
	if v.TunnelFails != 2 || v.TunnelState != "degraded" {
		t.Fatalf("expected degraded/2, got state=%q, fails=%d", v.TunnelState, v.TunnelFails)
	}

	// 3. Stale success must not clear current session's failure count
	m.recordProbe("a", "A", staleGen, staleSess, nil, true)
	v, _ = m.View("a")
	if v.TunnelFails != 2 || v.TunnelState != "degraded" {
		t.Fatalf("stale success cleared current failures: state=%q, fails=%d", v.TunnelState, v.TunnelFails)
	}

	// 4. Stale 3rd failure must not kill current session
	m.recordProbe("a", "A", staleGen, staleSess, errors.New("old 3rd failure"), true)
	v, _ = m.View("a")
	if v.State != StateOnline || v.TunnelState == "dead" {
		t.Fatalf("stale 3rd failure killed current session: state=%v, tunnel=%q", v.State, v.TunnelState)
	}
}

func TestHostUnreachableDoesNotKillTunnel(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	cfg.Settings.HealthIntervalSec = 60
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	sess := conn.session("a")
	// Simulate SOCKS5 0x04 Host unreachable error from remote server
	sess.dialErr = errors.New("socks connect tcp 127.0.0.1:59918->10.240.32.225:443: unknown error host unreachable")

	m.mu.Lock()
	m.points["a"].info.Apps = tunnelApps()
	m.points["a"].info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.240.32.225", Max: "10.240.32.225", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	m.points["a"].lastTraffic = time.Time{}
	m.mu.Unlock()

	// Probe 5 times - should NEVER kill the tunnel
	for i := 0; i < 5; i++ {
		probeNow(m, "a")
	}

	v, _ := m.View("a")
	if v.State != StateOnline {
		t.Fatalf("state = %v, want still StateOnline after host unreachable probe errors", v.State)
	}
	if v.TunnelState == "dead" {
		t.Fatalf("tunnel state = dead, want degraded but alive")
	}
}

func TestRecentTrafficProtectsTunnelFromDead(t *testing.T) {
	conn := &fakeConnector{}
	cfg := testConfig(model.AccessPoint{
		ID: "a", Name: "A", Server: "a.example", Port: 443, Username: "u", InPool: true,
	})
	cfg.Settings.HealthIntervalSec = 60
	m := newTestManager(t, conn.Connect, cfg)
	m.Connect("a")
	waitFor(t, "online", func() bool {
		v, _ := m.View("a")
		return v.State == StateOnline
	})
	sess := conn.session("a")
	sess.dialErr = errors.New("fatal tunnel connection reset")

	m.mu.Lock()
	m.points["a"].info.Apps = tunnelApps()
	m.points["a"].info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.1.2.3", Max: "10.1.2.3", PortMin: 3306, PortMax: 3306, Protocol: "tcp"}}}
	// Recent traffic happened 10 seconds ago
	m.points["a"].lastTraffic = time.Now().Add(-10 * time.Second)
	m.mu.Unlock()

	// Probe 3 times with fatal error while recent traffic exists
	for i := 0; i < 3; i++ {
		probeNow(m, "a")
	}

	v, _ := m.View("a")
	if v.State != StateOnline {
		t.Fatalf("state = %v, recent traffic should prevent tunnel termination", v.State)
	}
	if v.TunnelState == "dead" {
		t.Fatalf("tunnel state = %q, want degraded due to recent traffic protection", v.TunnelState)
	}
}

func TestLastSuccessfulTargetPreferredForProbe(t *testing.T) {
	info := SessionInfo{
		Resources: &workeripc.ResourceSnapshot{
			IPRules: []workeripc.IPRule{
				{Min: "10.240.32.225", Max: "10.240.32.225", PortMin: 443, PortMax: 443, Protocol: "tcp"},
				{Min: "192.168.132.16", Max: "192.168.132.16", PortMin: 9011, PortMax: 9011, Protocol: "tcp"},
			},
		},
	}
	// Without preferred, picks first rule
	target1 := healthTarget(info)
	if target1 != "10.240.32.225:443" {
		t.Fatalf("got %q, want 10.240.32.225:443", target1)
	}

	// With preferred active target, picks preferred
	target2 := healthTarget(info, "192.168.132.16:9011")
	if target2 != "192.168.132.16:9011" {
		t.Fatalf("got %q, want 192.168.132.16:9011", target2)
	}
}

func TestConfiguredHealthTargetOverridesAndFallsBack(t *testing.T) {
	info := SessionInfo{
		Resources: &workeripc.ResourceSnapshot{
			IPRules: []workeripc.IPRule{
				{Min: "10.240.32.225", Max: "10.240.32.225", PortMin: 443, PortMax: 443, Protocol: "tcp"},
				{Min: "192.168.132.16", Max: "192.168.132.16", PortMin: 9011, PortMax: 9011, Protocol: "tcp"},
			},
		},
	}

	// 1. 未配置任何 HealthTarget 时：降级走原逻辑，优先取第一个合规规则
	if got := healthTarget(info); got != "10.240.32.225:443" {
		t.Fatalf("未配置降级失败：got %q, want 10.240.32.225:443", got)
	}

	// 2. 配置了具体的 host:port 时：优先返回配置的目标
	infoWithHostPort := info
	infoWithHostPort.HealthTarget = "192.168.132.16:9011"
	if got := healthTarget(infoWithHostPort); got != "192.168.132.16:9011" {
		t.Fatalf("配置 host:port 覆盖失败：got %q, want 192.168.132.16:9011", got)
	}

	// 3. 配置了完整 http/https URL 时：解析出 host:port 并优先返回
	infoWithURL := info
	infoWithURL.HealthTarget = "http://192.168.132.16:9011/api/health"
	if got := healthTarget(infoWithURL); got != "192.168.132.16:9011" {
		t.Fatalf("配置 HTTP URL 提取覆盖失败：got %q, want 192.168.132.16:9011", got)
	}

	// 4. 配置了带域名的 HTTPS URL
	infoDomain := SessionInfo{
		HealthTarget: "https://oa.test.com/login",
		Resources: &workeripc.ResourceSnapshot{
			DomainRules: []workeripc.DomainRule{
				{Domain: "oa.test.com", PortMin: 443, PortMax: 443, Protocol: "tcp"},
			},
		},
	}
	if got := healthTarget(infoDomain); got != "oa.test.com:443" {
		t.Fatalf("配置 HTTPS 域名覆盖失败：got %q, want oa.test.com:443", got)
	}
}
