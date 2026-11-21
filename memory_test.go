package main

import (
	"testing"
	"time"
)

// 修剪的判定只看两件事：不在前台够久、且这段时间没有流量。
func TestShouldTrim(t *testing.T) {
	cases := []struct {
		name   string
		hidden time.Duration
		idle   time.Duration
		want   bool
	}{
		{"刚藏起来", 5 * time.Second, 10 * time.Minute, false},
		{"藏够久但有流量", time.Minute, 2 * time.Second, false},
		{"藏够久且长时间无流量", time.Minute, time.Minute, true},
		{"边界：恰好 30 秒", trimHiddenFor, trimIdleFor, true},
		{"边界：差一秒", trimHiddenFor - time.Second, trimIdleFor, false},
	}
	for _, c := range cases {
		if got := shouldTrim(c.hidden, c.idle); got != c.want {
			t.Errorf("%s：shouldTrim(%v, %v) = %v，想要 %v", c.name, c.hidden, c.idle, got, c.want)
		}
	}
}

// 流量刻度只在真的变了的时候才更新时间戳。
func TestNoteTrafficUpdatesIdleClock(t *testing.T) {
	s := &idleState{}
	now := time.Now()
	if s.noteTraffic(0, now) {
		t.Error("刻度没变时不该报告更新")
	}
	if !s.noteTraffic(5, now) {
		t.Fatal("刻度变了就该记一笔流量")
	}
	s.mu.Lock()
	mark := s.trafficMark
	s.mu.Unlock()
	if mark != 5 {
		t.Errorf("刻度 = %d，想要 5", mark)
	}
	// 同样的刻度再来一次不算新流量：无流量阈值才能成立。
	if s.noteTraffic(5, now.Add(time.Minute)) {
		t.Error("刻度相同时不该刷新流量时间")
	}
}

// 隐藏/最小化开始计时，回到前台清掉；一次隐藏只修剪一次。
func TestIdleStateDue(t *testing.T) {
	now := time.Now()
	s := &idleState{}
	s.begin(now)
	// 刚进后台：两个时长都还不到阈值。
	if s.due(now) {
		t.Fatal("刚进后台不该修剪")
	}
	// 一分钟后仍无新流量：应当修剪，且只修一次。
	if !s.due(now.Add(time.Minute)) {
		t.Fatal("够久且无流量时应当修剪")
	}
	if s.due(now.Add(time.Minute)) {
		t.Error("同一轮不该重复修剪")
	}
	// 回到前台后再进后台：重新允许修剪。
	s.end()
	s.begin(now.Add(-time.Hour))
	s.mu.Lock()
	s.lastTrafficAt = now.Add(-time.Hour)
	s.mu.Unlock()
	if !s.due(now) {
		t.Error("新一轮隐藏应当重新允许修剪")
	}
}

// 只有「不在前台够久 + 无流量」才修剪，而且一次只修一次。
func TestMaybeTrimMemoryGating(t *testing.T) {
	a := testApp(t)
	trims := 0
	a.trimMemoryFn = func() { trims++ }
	now := time.Now()

	// 可见时不修。
	a.idle.begin(now.Add(-2 * time.Hour))
	a.maybeTrimMemory()
	if trims != 0 {
		t.Fatalf("窗口可见时不该修剪，实际修了 %d 次", trims)
	}

	// 隐藏但刚有流量：不修。
	a.windowHidden.Store(true)
	a.idle.begin(now)
	a.idle.noteTraffic(a.trafficTotal()+1, now)
	a.maybeTrimMemory()
	if trims != 0 {
		t.Fatalf("刚有流量时不该修剪，实际修了 %d 次", trims)
	}

	// 隐藏够久且长时间无流量：修一次。
	a.idle.begin(now.Add(-time.Hour))
	a.idle.mu.Lock()
	a.idle.lastTrafficAt = now.Add(-time.Hour)
	a.idle.mu.Unlock()
	a.maybeTrimMemory()
	if trims != 1 {
		t.Fatalf("应当修剪一次，实际 %d 次", trims)
	}
	// 同一轮隐藏再调也不重复修剪。
	a.maybeTrimMemory()
	if trims != 1 {
		t.Errorf("一次隐藏只该修一次，实际 %d 次", trims)
	}
}

// 隐藏时 UI 重绘必须是 0 次：这是验收口径，不是感觉。
func TestHiddenMeansZeroRepaints(t *testing.T) {
	a := &app{}
	a.windowHidden.Store(true)
	for i := 0; i < 20; i++ {
		a.invalidate()
		a.invalidateCoalesced()
		a.invalidateLogSlow()
	}
	_, _, draws, _, gated := a.redrawCounts()
	if draws != 0 {
		t.Fatalf("隐藏时重绘 %d 次，要求 0 次", draws)
	}
	if gated != 60 {
		t.Errorf("三次入口 × 20 轮都该被门控记下，实际 %d", gated)
	}
}
