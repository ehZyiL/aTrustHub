package main

import (
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// 内存策略只做两件事，而且都做得保守：
//   - 启动时给 Go 一个软上限，避免异常情况把内存吃穿（GOGC 保持默认 100，
//     降 GC 百分比换来的是更频繁的 GC，与「省 CPU」的目标相悖）；
//   - 只有在「藏进托盘或最小化 ≥30 秒，而且这段时间没有新流量」时才修剪一次工作集。
//
// 修剪（FreeOSMemory / SetProcessWorkingSetSize）会把页面换出去，
// 下次唤醒要重新缺页读回来；隐藏一两秒就做，等于给自己制造卡顿。
const (
	// memoryLimitBytes 是 Go runtime 的软内存上限。
	memoryLimitBytes = 128 << 20
	// trimHiddenFor 是「藏得够久」的阈值。
	trimHiddenFor = 30 * time.Second
	// trimIdleFor 是「没有流量」的阈值。
	trimIdleFor = 30 * time.Second
)

// shouldTrim 决定这次隐藏期间要不要修剪工作集。
func shouldTrim(hiddenFor, idleFor time.Duration) bool {
	return hiddenFor >= trimHiddenFor && idleFor >= trimIdleFor
}

// idleState 记录「多久没在前台、多久没流量」。
//
// 它同时被 UI 线程（隐藏/最小化/还原/可见性校正）和 1 秒状态 ticker
// （记流量、判断修剪）读写，所以字段全部私有不外露，进出都走锁：
// 一边写 time.Time、一边读 time.Time 是会撕裂的。
type idleState struct {
	mu            sync.Mutex
	hiddenSince   time.Time
	lastTrafficAt time.Time
	trafficMark   int64
	trimmed       bool
}

// begin 记下「这一刻开始不在前台」，并允许本轮再修剪一次。
func (s *idleState) begin(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hiddenSince = now
	if s.lastTrafficAt.IsZero() {
		s.lastTrafficAt = now
	}
	s.trimmed = false
}

// end 是回到前台：清掉计时，允许下一轮重新修剪。
func (s *idleState) end() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hiddenSince = time.Time{}
	s.trimmed = false
}

// noteTraffic 在累计刻度变化时记一笔流量时间；返回是否真的更新了。
func (s *idleState) noteTraffic(total int64, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if total == s.trafficMark {
		return false
	}
	s.trafficMark = total
	s.lastTrafficAt = now
	return true
}

// periods 返回「不在前台多久」与「多久没流量」，零值按「一直」处理。
func (s *idleState) periods(now time.Time) (hiddenFor, idleFor time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hiddenFor = now.Sub(s.hiddenSince)
	idleFor = time.Duration(1<<62 - 1)
	if !s.lastTrafficAt.IsZero() {
		idleFor = now.Sub(s.lastTrafficAt)
	}
	return hiddenFor, idleFor
}

// due 判断现在要不要修剪；返回 true 时顺手记下「本轮已经修剪过」，
// 保证一次隐藏/最小化只修剪一次。
func (s *idleState) due(now time.Time) bool {
	hiddenFor, idleFor := s.periods(now)
	if !shouldTrim(hiddenFor, idleFor) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trimmed {
		return false
	}
	s.trimmed = true
	return true
}

// trafficTotal 是累计到现在的流量刻度：接入点的连接计数，加上本机项目
// 的连接数与收发字节。它只需要单调变化，用来判断「有没有新流量」。
func (a *app) trafficTotal() int64 {
	var n int64
	if a.mgr != nil {
		for _, v := range a.mgr.Views() {
			n += v.Total
		}
	}
	for _, p := range a.cfg.LocalApps {
		c := a.localView(p.ID).Connections
		n += int64(c.Opened) + int64(c.Sent>>10) + int64(c.Received>>10)
	}
	return n
}

// noteTraffic 在状态 ticker 里每秒调一次：刻度变了就记一笔流量时间。
func (a *app) noteTraffic() {
	a.idle.noteTraffic(a.trafficTotal(), time.Now())
}

// maybeTrimMemory 在状态 ticker 里调：不在前台且「够久没动」才修剪。
func (a *app) maybeTrimMemory() {
	if a.windowVisible() {
		return
	}
	if !a.idle.due(time.Now()) {
		return
	}
	a.trimMemory()
}

// trimMemory 是真正的修剪：先让 Go 回收，再让系统把工作集换出去。
// 日志里带上修剪前后的常驻内存，因为“省了多少”是用户真正关心的事，
// 而 Linux 上 trimWorkingSet 是空实现（靠 FreeOSMemory 自己归运）。
func (a *app) trimMemory() {
	if a.trimMemoryFn != nil {
		a.trimMemoryFn()
		return
	}
	before := residentBytes()
	runtime.GC()
	debug.FreeOSMemory()
	trimWorkingSet()
	if a.mgr != nil {
		a.mgr.TrimSessions()
	}
	after := residentBytes()
	if before > 0 && after > 0 {
		a.tunLogf("窗口不在前台 %s 且无流量，已修剪工作集：常驻 %.1f MB → %.1f MB",
			trimHiddenFor, float64(before)/(1<<20), float64(after)/(1<<20))
		return
	}
	a.tunLogf("窗口不在前台 %s 且无流量，已修剪工作集", trimHiddenFor)
}
