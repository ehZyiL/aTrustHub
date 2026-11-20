package main

import (
	"runtime"
	"testing"
)

func TestExternalProxyReplacementReleasesStaleSwitchAndPreservesSettings(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows shared proxy ownership")
	}
	originalOwned, originalApply := systemProxyOwnedFn, applySystemProxyFn
	t.Cleanup(func() { systemProxyOwnedFn, applySystemProxyFn = originalOwned, originalApply })
	systemProxyOwnedFn = func(string) bool { return false }
	writes := 0
	applySystemProxyFn = func(string, bool) error { writes++; return nil }
	for _, action := range []string{"guard", "exit", "toggle"} {
		t.Run(action, func(t *testing.T) {
			a := testApp(t)
			a.sysProxyOn, a.sysProxySwitch = true, true
			switch action {
			case "guard":
				a.guardSystemProxy()
			case "exit":
				a.disableSystemProxyOnExit()
			case "toggle":
				a.toggleSystemProxy()
			}
			if a.sysProxyOn || a.sysProxySwitch || writes != 0 {
				t.Fatal("stale proxy ownership overwrote external settings")
			}
		})
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
