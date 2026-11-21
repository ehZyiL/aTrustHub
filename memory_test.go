package main

import (
	"testing"
	"time"
)

// 修剪的判定只看两件事：藏得够久、且这段时间没有流量。
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
	a := testApp(t)
	// 刻度不变：不碰时间戳，否则「无流量」永远不成立。
	old := time.Now().Add(-time.Hour)
	a.lastTrafficAt = old
	a.trafficMark = a.trafficTotal()
	a.noteTraffic()
	if !a.lastTrafficAt.Equal(old) {
		t.Errorf("刻度没变却把流量时间改成了 %v", a.lastTrafficAt)
	}

	// 刻度变了：立刻刷新，作为「刚有流量」的证据。
	a.trafficMark = a.trafficTotal() - 1
	a.noteTraffic()
	if time.Since(a.lastTrafficAt) > time.Minute {
		t.Errorf("刻度变了却没更新流量时间（%v）", a.lastTrafficAt)
	}
}

// 只有「隐藏够久 + 无流量」才修剪，而且一次隐藏只修一次。
func TestMaybeTrimMemoryGating(t *testing.T) {
	a := testApp(t)
	trims := 0
	a.trimMemoryFn = func() { trims++ }

	// 可见时不修。
	a.hiddenSince = time.Now().Add(-2 * time.Hour)
	a.lastTrafficAt = time.Now().Add(-2 * time.Hour)
	a.maybeTrimMemory()
	if trims != 0 {
		t.Fatalf("窗口可见时不该修剪，实际修了 %d 次", trims)
	}

	// 隐藏但刚有流量：不修。
	a.windowHidden.Store(true)
	a.lastTrafficAt = time.Now()
	a.maybeTrimMemory()
	if trims != 0 {
		t.Fatalf("刚有流量时不该修剪，实际修了 %d 次", trims)
	}

	// 隐藏够久且长时间无流量：修一次。
	a.hiddenSince = time.Now().Add(-time.Hour)
	a.lastTrafficAt = time.Now().Add(-time.Hour)
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
