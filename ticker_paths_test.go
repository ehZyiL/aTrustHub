package main

import (
	"sync"
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
)

// N7 regression: every helper the state ticker reaches must be safe while the UI
// thread republishes the configuration. Run this under -race (WSL Debian has a C
// compiler); without the detector it still catches deadlocks and panics.
func TestTickerPathsReadConfigUnderLock(t *testing.T) {
	a := testApp(t)
	originalOwned, originalApply, originalForeign := systemProxyOwnedFn, applySystemProxyFn, systemProxyForeignFn
	t.Cleanup(func() {
		systemProxyOwnedFn, applySystemProxyFn, systemProxyForeignFn = originalOwned, originalApply, originalForeign
	})
	// Keep the guard path off the real registry and off the network.
	systemProxyOwnedFn = func(string) bool { return true }
	applySystemProxyFn = func(string, bool) error { return nil }
	systemProxyForeignFn = func(string) bool { return false }
	a.sysProxyOn.Store(true)

	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The UI thread saving settings over and over.
		for i := 0; i < 500; i++ {
			cfg := a.store.Config()
			cfg.Settings.AggregatePort = 1080 + i%7
			a.setConfig(cfg)
		}
		close(done)
	}()

	for {
		select {
		case <-done:
			wg.Wait()
			return
		default:
		}
		// Everything the 1s/3s loops call, in the same order they use.
		a.systemProxyAddress()
		a.hasPointWithProtocol(model.ProtocolATrust)
		a.hasPointWithProtocol(model.ProtocolEasyConnect)
		a.canUseGlobalTUN()
		a.guardSystemProxy()
		a.noteTraffic()
		a.configForBackground()
		a.checkTunnels()
	}
}
