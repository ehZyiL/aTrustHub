package main

import (
	"sync"
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
)

// N7: background loops read the configuration through a copy, so a whole-struct
// reassignment on the UI thread can never be observed half-written.
func TestConfigSnapshotIsACopy(t *testing.T) {
	a := testApp(t)
	live := a.configForBackground()
	livePoints := len(live.Points)

	copied := a.configForBackground()
	copied.Settings.ListenHost = "0.0.0.0"
	copied.Settings.HealthIntervalSec = 12345
	copied.LocalApps = append(copied.LocalApps, live.LocalApps...)
	copied.Points = append(copied.Points, live.Points...)

	again := a.configForBackground()
	if again.Settings.ListenHost == "0.0.0.0" || again.Settings.HealthIntervalSec == 12345 {
		t.Fatal("a background reader can mutate the live settings")
	}
	if len(again.Points) != livePoints || len(again.LocalApps) != len(live.LocalApps) {
		t.Fatal("a background reader can mutate the live lists")
	}
}

// The lock has to hold under concurrent writers and readers; a deadlock or a
// panic here would be obvious even without the race detector.
func TestConfigSnapshotUnderConcurrentWrites(t *testing.T) {
	a := testApp(t)
	const rounds = 2000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			cfg := a.store.Config()
			cfg.Settings.HealthIntervalSec = i
			a.setConfig(cfg)
		}
	}()
	seen := 0
	for i := 0; i < rounds; i++ {
		cfg := a.configForBackground()
		if cfg.Settings.ListenHost != "" {
			seen++
		}
	}
	wg.Wait()
	if seen == 0 {
		t.Fatal("background reads returned an empty configuration")
	}
}

// mutateConfig edits under the write lock; the change must be visible to the
// next snapshot.
func TestMutateConfigPublishesChange(t *testing.T) {
	a := testApp(t)
	a.mutateConfig(func(cfg *model.Config) { cfg.Settings.HealthIntervalSec = 4242 })
	if got := a.configForBackground().Settings.HealthIntervalSec; got != 4242 {
		t.Fatalf("health interval = %d, want 4242", got)
	}
}
