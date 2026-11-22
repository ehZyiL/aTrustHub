package main

import (
	"runtime"
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
	originalOwned, originalApply := systemProxyOwnedFn, applySystemProxyFn
	p := &proxyCalls{owned: owned}
	systemProxyOwnedFn = owned
	applySystemProxyFn = p.apply
	t.Cleanup(func() {
		systemProxyOwnedFn, applySystemProxyFn = originalOwned, originalApply
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
		{Enabled: 1, Server: "socks=127.0.0.1:1080", Automatic: true},
	} {
		if ownsProxy(snapshot, "127.0.0.1:1080") {
			t.Fatal("unowned settings accepted", snapshot)
		}
	}
	if !ownsProxy(captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080"}, "127.0.0.1:1080") {
		t.Fatal("own endpoint not recognized")
	}
}
