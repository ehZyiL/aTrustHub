package desktop

import (
	"fmt"
	"runtime"
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

// 状态 ticker 每秒只看本机项目的 ID；它拿到的必须是独立快照，而不是活配置里的切片。
func TestLocalAppIDsAreIndependentSnapshot(t *testing.T) {
	a := testApp(t)
	cfg := a.store.Config()
	cfg.LocalApps = []model.LocalApp{{ID: "first"}, {ID: "second"}}
	a.setConfig(cfg)

	ids := a.localAppIDsForBackground()
	if len(ids) != 2 || ids[0] != "first" || ids[1] != "second" {
		t.Fatalf("ids = %v, want [first second]", ids)
	}
	if cap(ids) != len(ids) {
		t.Fatalf("snapshot shares spare capacity with the live slice: len=%d cap=%d", len(ids), cap(ids))
	}

	// 活配置变了，已经拿到的快照不能跟着变。
	cfg = a.store.Config()
	cfg.LocalApps = []model.LocalApp{{ID: "third"}}
	a.setConfig(cfg)
	if ids[0] != "first" {
		t.Fatalf("a later config change rewrote the previously returned snapshot: %v", ids)
	}
	if now := a.localAppIDsForBackground(); len(now) != 1 || now[0] != "third" {
		t.Fatalf("next read = %v, want [third]", now)
	}
}

// 与写线程并发时不能撕裂（-race 下暴露）。
func TestLocalAppIDsUnderConcurrentWrites(t *testing.T) {
	a := testApp(t)
	const rounds = 500
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			cfg := a.store.Config()
			cfg.LocalApps = []model.LocalApp{{ID: fmt.Sprintf("app-%d", i)}}
			a.setConfig(cfg)
		}
	}()
	for i := 0; i < rounds; i++ {
		a.trafficTotal()
	}
	wg.Wait()
}

// 回归护栏：每秒的流量刻度只能读 ID，不能顺带克隆整份配置。
// 用「一次 Clone 的分配量」当基准自校准，避免写死字节数。
func TestTrafficTotalDoesNotCloneConfig(t *testing.T) {
	a := testApp(t)
	cfg := a.store.Config()
	cfg.LocalApps = nil
	// 大配置：每个项目带一堆参数，克隆成本随配置线性增长。
	for i := 0; i < 200; i++ {
		cfg.LocalApps = append(cfg.LocalApps, model.LocalApp{
			ID:   fmt.Sprintf("app-%d", i),
			Args: make([]string, 64),
		})
	}
	a.setConfig(cfg)

	// 基准：一次 configForBackground() 实际分配多少。
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	snapshot := a.configForBackground()
	runtime.ReadMemStats(&after)
	cloneBytes := after.TotalAlloc - before.TotalAlloc
	runtime.KeepAlive(snapshot)
	if cloneBytes == 0 {
		t.Fatal("clone allocated nothing; the baseline is not measurable")
	}

	a.trafficTotal() // 预热：首次调用可能有一次性分配
	const rounds = 50
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		a.trafficTotal()
	}
	runtime.ReadMemStats(&after)
	perCall := (after.TotalAlloc - before.TotalAlloc) / rounds

	if perCall > cloneBytes/4 {
		t.Fatalf("trafficTotal allocates %d B per call, a whole clone costs %d B: the ticker is cloning the config again", perCall, cloneBytes)
	}
}

// 每秒一次的热路径，用基准把「每调用多少字节」变成可重复测的数字。
func BenchmarkTrafficTotal(b *testing.B) {
	a := testApp(new(testing.T))
	cfg := a.store.Config()
	cfg.LocalApps = nil
	for i := 0; i < 5; i++ {
		cfg.LocalApps = append(cfg.LocalApps, model.LocalApp{ID: fmt.Sprintf("app-%d", i)})
	}
	a.setConfig(cfg)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.trafficTotal()
	}
}
