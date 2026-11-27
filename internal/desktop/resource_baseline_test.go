package desktop

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
)

// This is an opt-in measurement harness, not a claim about live VPN memory.
// It uses the production share/discovery controllers, a real local listener and
// fake VPN/multicast backends. No credentials, firewall changes or gateways.
func TestOptionalResourceBaseline(t *testing.T) {
	if os.Getenv("CONNECT_HUB_MEASURE_RESOURCES") != "1" {
		t.Skip("set CONNECT_HUB_MEASURE_RESOURCES=1 to record lifecycle measurements")
	}
	sample := func(stage string, stoppedIn time.Duration) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		b, err := json.Marshal(struct {
			Stage      string `json:"stage"`
			HeapAlloc  uint64 `json:"heap_alloc"`
			HeapInuse  uint64 `json:"heap_inuse"`
			RuntimeSys uint64 `json:"runtime_sys"`
			Resident   int64  `json:"resident"`
			Goroutines int    `json:"goroutines"`
			StopMicros int64  `json:"stop_micros"`
		}{stage, m.HeapAlloc, m.HeapInuse, m.Sys, residentBytes(), runtime.NumGoroutine(), stoppedIn.Microseconds()})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("RESOURCE_BASELINE " + string(b))
	}
	runtime.GC()
	sample("before-setup", 0)
	a, backend, iface, _ := discoveryApp(t)
	sample("unused", 0)
	a.openLANShare()
	_ = ui.NewTester(a.view, 1120, 800).Texts()
	sample("panel-only", 0)
	runtime.GC()
	sample("panel-after-gc", 0)
	a.openLANDiscovery()
	waitLANBrowse(t, a)
	sample("browsing", 0)
	a.closeLANDiscovery()
	for i := 0; i < 10; i++ {
		enableShare(t, a, iface, true, "resource-fixture")
		waitCondition(t, "fixture announcement", func() bool { return backend.liveCount() == 1 })
		if i == 0 {
			sample("sharing-and-publishing", 0)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		err := a.lanShare.Disable(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		waitCondition(t, "fixture withdrawn", func() bool { return backend.liveCount() == 0 })
		sample("disabled", time.Since(start))
	}
	// Retention sample is explicitly after GC; never confuse it with normal RSS.
	runtime.GC()
	sample("ten-cycles-after-gc", 0)
	a.shutdownLANDiscovery()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.lanShare.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	sample("shutdown", 0)
}
