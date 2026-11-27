package desktop

import (
	"sync"
	"testing"
	"time"
)

// fakeSchedule 记录最近一次排队的回调，测试自己决定什么时候触发。
type fakeSchedule struct {
	mu      sync.Mutex
	pending func()
	delay   time.Duration
	starts  int
	stops   int
}

func (f *fakeSchedule) schedule(d time.Duration, fn func()) func() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = fn
	f.delay = d
	f.starts++
	return func() {
		f.mu.Lock()
		f.stops++
		f.pending = nil
		f.mu.Unlock()
	}
}

// fire 手动触发排队的回调，模拟定时器到点。
func (f *fakeSchedule) fire() {
	f.mu.Lock()
	fn := f.pending
	f.pending = nil
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (f *fakeSchedule) armed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending != nil
}

// newTestScheduler 组一个用手动时钟的调度器。
func newTestScheduler(interval time.Duration, visible func() bool, draws *int) (*redrawScheduler, *fakeSchedule) {
	fake := &fakeSchedule{}
	var mu sync.Mutex
	s := newRedrawScheduler(interval, visible, func() {
		mu.Lock()
		*draws++
		mu.Unlock()
	})
	s.schedule = fake.schedule
	return s, fake
}

// 事件源的多条请求合并成一帧：这也是 30 FPS 上限的来源。
func TestRedrawSchedulerCoalescesBursts(t *testing.T) {
	draws := 0
	s, fake := newTestScheduler(33*time.Millisecond, func() bool { return true }, &draws)
	for i := 0; i < 10; i++ {
		s.request()
	}
	if fake.starts != 1 {
		t.Errorf("10 条事件只该排一次帧，实际 %d 次", fake.starts)
	}
	if fake.delay != 33*time.Millisecond {
		t.Errorf("间隔 = %v，想要 33ms", fake.delay)
	}
	if draws != 0 {
		t.Errorf("定时器没到点就不该画，实际画了 %d 次", draws)
	}
	fake.fire()
	if draws != 1 {
		t.Errorf("到点应当只画一帧，实际 %d", draws)
	}
	if _, coalesced, _ := s.stats(); coalesced != 9 {
		t.Errorf("应当合并掉 9 条，实际 %d", coalesced)
	}
	// 合并完之后再来的事件，会重新排一帧。
	s.request()
	if !fake.armed() {
		t.Error("下一批事件应当重新排队")
	}
}

// 交互路径不等定时器：立刻画，并把待发的合并帧取消掉。
func TestRedrawSchedulerImmediateDrawsAndCancels(t *testing.T) {
	draws := 0
	s, fake := newTestScheduler(33*time.Millisecond, func() bool { return true }, &draws)
	s.request()
	if !fake.armed() {
		t.Fatal("事件源请求应当排队")
	}
	s.requestNow()
	if draws != 1 {
		t.Errorf("交互路径应当立刻画一帧，实际 %d", draws)
	}
	if fake.stops != 1 {
		t.Errorf("应当取消掉待发的合并帧，实际取消 %d 次", fake.stops)
	}
	// 取消之后即便定时器再响，也不该重复画。
	fake.fire()
	if draws != 1 {
		t.Errorf("取消后的定时器不该再画，实际 %d 帧", draws)
	}
}

// 窗口隐藏时一路都不画：这正是「隐藏时 UI 重绘 0 次」的验收口径。
func TestRedrawSchedulerGateWhenHidden(t *testing.T) {
	draws := 0
	visible := false
	s, fake := newTestScheduler(33*time.Millisecond, func() bool { return visible }, &draws)
	for i := 0; i < 5; i++ {
		s.request()
		s.requestNow()
	}
	if fake.starts != 0 {
		t.Errorf("隐藏时不该排队，实际排了 %d 次", fake.starts)
	}
	if draws != 0 {
		t.Fatalf("隐藏时重绘必须是 0 次，实际 %d 次", draws)
	}
	if _, _, gated := s.stats(); gated != 10 {
		t.Errorf("隐藏时应当记 10 次丢弃，实际 %d", gated)
	}
	// 排队期间窗口被藏起来：到点也不画。
	visible = true
	s.request()
	visible = false
	fake.fire()
	if draws != 0 {
		t.Errorf("排队后变隐藏也不该画，实际 %d 次", draws)
	}
	// 恢复可见后照常画。
	visible = true
	s.requestNow()
	if draws != 1 {
		t.Errorf("恢复可见后应当画一帧，实际 %d", draws)
	}
}

// app 层的两个入口：交互即时、事件源合并。
func TestAppInvalidatePaths(t *testing.T) {
	a := &app{}
	a.windowHidden.Store(true)
	a.invalidate()
	a.invalidateCoalesced()
	fastDraws, slowDraws, draws, _, gated := a.redrawCounts()
	if draws != 0 || fastDraws != 0 || slowDraws != 0 {
		t.Fatalf("隐藏时重绘必须是 0 次，实际 %d", draws)
	}
	if gated != 2 {
		t.Errorf("隐藏时两次请求都该记丢弃，实际 %d", gated)
	}
	a.windowHidden.Store(false)
	a.invalidate()
	if _, _, draws, _, _ := a.redrawCounts(); draws != 1 {
		t.Errorf("可见时交互请求应当画一帧，实际 %d", draws)
	}
}
