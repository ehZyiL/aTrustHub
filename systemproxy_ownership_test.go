package main

import (
	"runtime"
	"strings"
	"sync"
	"testing"
)

// proxyCalls records every write the app asks for, and keeps the journal
// directory empty so nothing can reach the real registry from a unit test.
type proxyCalls struct {
	mu      sync.Mutex
	targets []string
	on      []bool
	owned   func(string) bool
}

func (p *proxyCalls) apply(target string, on bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = append(p.targets, target)
	p.on = append(p.on, on)
	return nil
}

func (p *proxyCalls) writes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.targets)
}

func stubSystemProxySeams(t *testing.T, owned func(string) bool) *proxyCalls {
	t.Helper()
	originalOwned, originalApply, originalState := systemProxyOwnedFn, applySystemProxyFn, systemProxyStateFn
	p := &proxyCalls{owned: owned}
	systemProxyOwnedFn = owned
	applySystemProxyFn = p.apply
	systemProxyStateFn = func(string) string { return "ProxyEnable=1，ProxyServer=socks=127.0.0.1:7890" }
	t.Cleanup(func() {
		systemProxyOwnedFn, applySystemProxyFn, systemProxyStateFn = originalOwned, originalApply, originalState
		setSystemProxyJournalDir("")
	})
	return p
}

func TestExternalProxyReplacementReleasesStaleSwitchAndPreservesSettings(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows shared proxy ownership")
	}
	p := stubSystemProxySeams(t, func(string) bool { return false })
	for _, action := range []string{"guard", "exit", "toggle"} {
		t.Run(action, func(t *testing.T) {
			a := testApp(t)
			a.sysProxyOn.Store(true)
			a.sysProxySwitch.Store(true)
			switch action {
			case "guard":
				a.guardSystemProxy()
			case "exit":
				a.disableSystemProxyOnExit()
			case "toggle":
				a.toggleSystemProxy()
			}
			if a.sysProxyOn.Load() || a.sysProxySwitch.Load() || p.writes() != 0 {
				t.Fatal("stale proxy ownership overwrote external settings")
			}
			// 日志要带上实测值，否则分不清是谁把设置抢走了。
			if action == "guard" {
				logged := ""
				for _, entry := range a.bus.Tail(20) {
					if strings.Contains(entry.Line, "本应用已停止管理该设置") {
						logged = entry.Line
					}
				}
				if !strings.Contains(logged, "socks=127.0.0.1:7890") {
					t.Fatalf("释放日志没有带上实测值：%q", logged)
				}
				// 代理由开变关，用户在首屏就能看到原因，不用去翻设置页的日志。
				if !strings.Contains(a.toast, "停止管理") || !strings.Contains(a.toast, "socks=127.0.0.1:7890") {
					t.Fatalf("释放时应当弹出提示并带上实测值，实际 %q", a.toast)
				}
			}
		})
	}
}

// A changed aggregate port leaves the registry on the address of the previous
// configuration. That is still our own value, so it must be re-pointed instead of
// being released as a third party's setting (which would leave the machine
// pointing at a dead port).
func TestChangedPortRepointsOwnStaleAddress(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows shared proxy ownership")
	}
	old := "127.0.0.1:1080"
	p := stubSystemProxySeams(t, func(addr string) bool { return addr == old })
	a := testApp(t)
	// The configured entry moved to another port since the journal was written.
	a.cfg.Settings.AggregatePort = 2080
	a.sysProxyOn.Store(true)
	a.sysProxySwitch.Store(true)
	if err := writeSystemProxyRecord(systemProxyJournalPath(a.dir), systemProxyRecord{
		Before:    captureProxySnapshot{Enabled: 0},
		Installed: captureProxySnapshot{Enabled: 1, Server: "socks=" + old},
	}); err != nil {
		t.Fatal(err)
	}

	if a.releaseLostSystemProxy() {
		t.Fatal("our own previous endpoint was released as a third party's")
	}
	if !a.sysProxyOn.Load() || !a.sysProxySwitch.Load() {
		t.Fatal("ownership was dropped")
	}
	want := a.systemProxyAddress()
	if want == old {
		t.Fatalf("test setup: configured address equals the stale one (%s)", want)
	}
	if p.writes() != 1 || p.targets[0] != want || !p.on[0] {
		t.Fatalf("writes = %v %v, want one apply of %q", p.targets, p.on, want)
	}
}

func TestProxyOwnershipRequiresEnabledMatchingManualEndpoint(t *testing.T) {
	for _, snapshot := range []captureProxySnapshot{
		{Enabled: 1, Server: "127.0.0.1:10808"},
		{Enabled: 0, Server: "socks=127.0.0.1:1080"},
	} {
		if ownsProxy(snapshot, "127.0.0.1:1080") {
			t.Fatal("unowned settings accepted", snapshot)
		}
	}
	// 自动检测开着不影响所有权：本应用不写 AutoDetect，而它在很多机器上默认就开着。
	// 把它算进所有权判断，等于在这类机器上永远不开自动接管，手动开完还会被当成
	// 丢失去关掉。
	if !ownsProxy(captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080", Automatic: true}, "127.0.0.1:1080") {
		t.Fatal("AutoDetect 开着时自家入口被误判成别人的设置")
	}
	if !ownsProxy(captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080"}, "127.0.0.1:1080") {
		t.Fatal("own endpoint not recognized")
	}
}

// 自动接管只在两种情况下退让：手动代理被别人占着，或者有 PAC 在管分流。
// 自动检测（AutoDetect）不算——它在很多机器上默认开着，也不妨碍手动代理生效。
func TestProxyForeignReason(t *testing.T) {
	const address = "127.0.0.1:1080"
	cases := []struct {
		name     string
		snapshot captureProxySnapshot
		blocked  bool
		want     string // 被拦下时，日志里必须出现的关键字
	}{
		{"没开系统代理时可以直接接管", captureProxySnapshot{}, false, ""},
		{"自家入口可以直接接管", captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080"}, false, ""},
		{"自动检测开着不阻碍", captureProxySnapshot{Enabled: 1, Server: "127.0.0.1:1080", Automatic: true}, false, ""},
		{"别人的代理不抢", captureProxySnapshot{Enabled: 1, Server: "127.0.0.1:10808", Automatic: true}, true, "127.0.0.1:10808"},
		{"PAC 在管分流时不抢", captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080", Automatic: true, PAC: true}, true, "PAC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := proxyForeignReason(c.snapshot, address)
			if (got != "") != c.blocked {
				t.Fatalf("proxyForeignReason(%+v) = %q, blocked 应为 %v", c.snapshot, got, c.blocked)
			}
			if c.blocked && !strings.Contains(got, c.want) {
				t.Fatalf("原因 %q 里没有 %q（日志要说清楚是谁占着）", got, c.want)
			}
		})
	}
}
