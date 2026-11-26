package main

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/discovery"
)

// Count the actual long-lived workers, not total goroutines (which includes
// unrelated runtime/UI work). This exercises the same setup as newApp.
func optionalWorkerStacks() []string {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	var found []string
	for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
		for _, marker := range []string{
			"/internal/relay.(*Controller).loop(",
			"/internal/relay/discovery.(*Publisher).loop(",
			".(*app).setupLANDiscovery.func",
			".(*app).runLANDiscoverySync(",
			".(*app).runLANDiscoverySearch(",
			"/internal/relay/discovery.(*Browser).expireLoop(",
		} {
			if strings.Contains(stack, marker) {
				found = append(found, stack)
				break
			}
		}
	}
	return found
}

func waitOptionalWorkers(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		stacks := optionalWorkerStacks()
		if len(stacks) <= baseline {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("optional workers did not stop within one second:\n%s", strings.Join(stacks, "\n\n"))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOptionalResourcesStopAndRestartTenTimes(t *testing.T) {
	baseline := len(optionalWorkerStacks())
	a, backend, iface, _ := discoveryApp(t)
	for i := 0; i < 10; i++ {
		enableShare(t, a, iface, true, "生命周期测试")
		waitCondition(t, "published", func() bool { return a.discoveryStatus().State == discovery.StatusPublished })
		a.openLANDiscovery()
		a.closeLANDiscovery()
		if !a.lanShare.View().Enabled {
			t.Fatal("closing the browser stopped sharing")
		}
		start := time.Now()
		if err := a.lanShare.Disable(context.Background()); err != nil {
			t.Fatal(err)
		}
		waitOptionalWorkers(t, baseline)
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("stop cycle %d took %v", i, elapsed)
		}
		if a.discoveryStatus().State != discovery.StatusIdle {
			t.Fatalf("cycle %d retained a publication", i)
		}
		if a.lanDisc.ui.snap.Candidates != nil || a.lanDisc.ui.cands != nil || len(a.lanDisc.browser.Snapshot().Candidates) != 0 {
			t.Fatal("closed browser retained candidates")
		}
	}
	if got := backend.liveCount(); got != 0 {
		t.Fatalf("retained %d announcements", got)
	}
	a.shutdownLANShare()
	a.kickLANDiscovery()
	a.openLANDiscovery()
	waitOptionalWorkers(t, baseline)
}

func TestUnusedSharingHasNoBackgroundTasks(t *testing.T) {
	a := testApp(t)
	a.discoveryBackend = newTestDiscoveryBackend()
	before := len(optionalWorkerStacks())
	a.setupLANShare()
	t.Cleanup(a.shutdownLANShare)
	// Give spawned workers a chance to enter their loop. The test still catches
	// them before the first two-second timer; no actual multicast is needed.
	time.Sleep(30 * time.Millisecond)
	stacks := optionalWorkerStacks()
	if len(stacks) > before {
		t.Fatalf("unused sharing started %d background tasks:\n%s", len(stacks)-before, strings.Join(stacks, "\n\n"))
	}
}
