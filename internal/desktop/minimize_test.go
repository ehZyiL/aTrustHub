package desktop

import (
	"testing"
	"time"
)

// 最小化与托盘隐藏是两个独立信号，任一成立就不画。
func TestWindowVisibleGateCoversMinimize(t *testing.T) {
	cases := []struct {
		name    string
		tray    bool
		min     bool
		visible bool
	}{
		{"正常可见", false, false, true},
		{"藏进托盘", true, false, false},
		{"最小化", false, true, false},
		{"两者都有", true, true, false},
	}
	for _, c := range cases {
		a := &app{}
		a.windowHidden.Store(c.tray)
		a.minimized.Store(c.min)
		if got := a.windowVisible(); got != c.visible {
			t.Errorf("%s：windowVisible = %v，想要 %v", c.name, got, c.visible)
		}
	}
}

// 最小化时所有入口都不画，还原后立刻补一帧。
func TestMinimizeSuspendsRepaints(t *testing.T) {
	a := &app{}
	a.onWindowMinimized()
	for i := 0; i < 10; i++ {
		a.invalidate()
		a.invalidateCoalesced()
		a.invalidateLogSlow()
	}
	_, _, draws, _, gated := a.redrawCounts()
	if draws != 0 {
		t.Fatalf("最小化时重绘必须是 0 次，实际 %d 次", draws)
	}
	if gated != 30 {
		t.Errorf("最小化时 30 次请求都该被丢弃，实际 %d", gated)
	}
	a.onWindowRestored()
	if _, _, draws, _, _ := a.redrawCounts(); draws != 1 {
		t.Errorf("还原后应当立刻补一帧，实际 %d", draws)
	}
}

// 最小化让工作集修剪走同一条「不在前台够久且无流量」的路。
func TestMinimizeArmsMemoryTrim(t *testing.T) {
	a := testApp(t)
	trims := 0
	a.trimMemoryFn = func() { trims++ }
	a.onWindowMinimized()
	if hidden, _ := a.idle.periods(time.Now()); hidden < 0 || hidden > time.Second {
		t.Fatalf("最小化应当刚开会计时，实际 %v", hidden)
	}
	// 刚最小化、又有流量：不修。
	a.idle.noteTraffic(a.trafficTotal()+1, time.Now())
	a.maybeTrimMemory()
	if trims != 0 {
		t.Fatalf("刚最小化且有流量时不该修剪，实际 %d 次", trims)
	}
	// 最小化够久且无流量：修一次。
	now := time.Now()
	a.idle.begin(now.Add(-time.Hour))
	a.idle.mu.Lock()
	a.idle.lastTrafficAt = now.Add(-time.Hour)
	a.idle.mu.Unlock()
	a.maybeTrimMemory()
	if trims != 1 {
		t.Fatalf("应当修剪一次，实际 %d 次", trims)
	}
	a.onWindowRestored()
	if a.minimized.Load() {
		t.Error("还原后最小化标记应当清掉")
	}
}

// 最小化时 IsVisible() 仍为 true，所以托盘标记的校正不能把它清掉。
func TestGateClearsRespectsMinimize(t *testing.T) {
	cases := []struct {
		visible, minimized, want bool
	}{
		{true, false, true},
		{true, true, false},
		{false, false, false},
		{false, true, false},
	}
	for _, c := range cases {
		if got := gateClears(c.visible, c.minimized); got != c.want {
			t.Errorf("gateClears(%v, %v) = %v，想要 %v", c.visible, c.minimized, got, c.want)
		}
	}
}
