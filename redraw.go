package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// 重绘调度把「要不要画」和「什么时候画」收在一处：
//   - 交互路径（点击、切页、勾选）走 requestNow，立刻画一帧；
//   - 事件源（日志行、巡检 ticker）走 request，按 interval 合并，
//     33ms 大致就是 30 FPS 的上限；
//   - 窗口藏在托盘时两路都不画，只记 gated，便于验证「隐藏时重绘 0 次」。
//
// schedule 是注入点：生产用 time.AfterFunc，测试用手动触发的假定时器，
// 这样节流逻辑可以在没有真实时钟的情况下断言。

// scheduleFunc 起一个延时任务，返回取消函数。
type scheduleFunc func(d time.Duration, fn func()) (stop func())

// timerSchedule 是生产用的定时器。
func timerSchedule(d time.Duration, fn func()) func() {
	t := time.AfterFunc(d, fn)
	return func() { t.Stop() }
}

// redrawScheduler 是「合并 + 门控 + 计数」三件事的实现。
type redrawScheduler struct {
	interval time.Duration
	schedule scheduleFunc
	visible  func() bool
	draw     func()

	mu      sync.Mutex
	pending bool
	stop    func()

	// stopped 置位后不再排新的帧（退出时用）。
	stopped atomic.Bool

	draws     atomic.Int64
	coalesced atomic.Int64
	gated     atomic.Int64
}

func newRedrawScheduler(interval time.Duration, visible func() bool, draw func()) *redrawScheduler {
	return &redrawScheduler{
		interval: interval,
		schedule: timerSchedule,
		visible:  visible,
		draw:     draw,
	}
}

// request 由事件源调用：把这一帧合并到最近的一个 interval 边界。
func (r *redrawScheduler) request() {
	if r.stopped.Load() {
		return
	}
	if !r.visibleNow() {
		r.gated.Add(1)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending {
		// 已经有待发的帧，这一条事件被合并掉。
		r.coalesced.Add(1)
		return
	}
	r.pending = true
	r.stop = r.schedule(r.interval, r.fire)
}

// requestNow 由交互路径调用：取消待发的合并帧，立刻画。
func (r *redrawScheduler) requestNow() {
	if r.stopped.Load() {
		return
	}
	if !r.visibleNow() {
		r.gated.Add(1)
		return
	}
	r.mu.Lock()
	stop := r.stop
	r.pending = false
	r.stop = nil
	r.mu.Unlock()
	if stop != nil {
		stop()
	}
	r.paint()
}

// fire 是定时器到点后的回调。
func (r *redrawScheduler) fire() {
	r.mu.Lock()
	r.pending = false
	r.stop = nil
	r.mu.Unlock()
	r.paint()
}

// paint 真正做一次重绘：出门控之前再查一次可见性，
// 这样「排了队但窗口刚好被藏起来」的那一帧也不会画。
func (r *redrawScheduler) paint() {
	if !r.visibleNow() {
		r.gated.Add(1)
		return
	}
	r.draws.Add(1)
	if r.draw != nil {
		r.draw()
	}
}

func (r *redrawScheduler) visibleNow() bool {
	return r.visible == nil || r.visible()
}

// stats 返回计数：画了几帧、合并掉几条、因隐藏丢弃几条。
func (r *redrawScheduler) stats() (draws, coalesced, gated int64) {
	return r.draws.Load(), r.coalesced.Load(), r.gated.Load()
}

// redrawIntervals 是两档间隔：高频事件按 30 FPS 合并，日志按 1 秒一次。
const (
	redrawFastInterval = 33 * time.Millisecond
	redrawSlowInterval = time.Second
)

// painter 惰性建好两档调度器：测试里的 app 是用结构体字面量搭的，
// 没有经过 newApp，所以这里不能依赖构造函数。
func (a *app) painter() *redrawScheduler {
	a.redrawOnce.Do(func() {
		visible := a.windowVisible
		a.redrawFast = newRedrawScheduler(redrawFastInterval, visible, a.paint)
		a.redrawSlow = newRedrawScheduler(redrawSlowInterval, visible, a.paint)
	})
	return a.redrawFast
}

// paint 是调度器最后一步：只做一件事，把窗口标脏。
// 窗口可能已经被销毁（退出时还有排队的定时器），所以这里要再确认一次。
func (a *app) paint() {
	if a.win == nil || a.win.IsDestroyed() {
		return
	}
	a.win.Invalidate()
}

// stopPainting 在退出前停掉两档调度器：不留定时器到窗口销毁之后。
func (a *app) stopPainting() {
	a.painter()
	a.redrawFast.stop()
	a.redrawSlow.stop()
}

// invalidate 是交互路径的入口：立即画，不做合并。
// 它不再推进任何业务状态——状态机由后台 ticker 负责。
func (a *app) invalidate() {
	a.painter().requestNow()
}

// invalidateCoalesced 是事件源（日志、巡检）的入口：33ms 合并。
func (a *app) invalidateCoalesced() {
	a.painter().request()
}

// invalidateLogSlow 给日志用：不在日志页时降到 1 秒一次。
func (a *app) invalidateLogSlow() {
	a.painter()
	a.redrawSlow.request()
}

// windowVisible 是门控信号：藏进托盘、或最小化到任务栏，都算不可见。
// 两条路都通：有托盘时可以关窗常驻，最小化则是不想离开窗口管理器时的做法。
func (a *app) windowVisible() bool {
	return !a.windowHidden.Load() && !a.minimized.Load()
}

// redrawCounts 给测试与排障用。
func (a *app) redrawCounts() (fast, slow, draws, coalesced, gated int64) {
	a.painter()
	_, c1, g1 := a.redrawFast.stats()
	_, c2, g2 := a.redrawSlow.stats()
	d1, _, _ := a.redrawFast.stats()
	d2, _, _ := a.redrawSlow.stats()
	return d1, d2, d1 + d2, c1 + c2, g1 + g2
}
