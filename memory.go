package main

import (
	"runtime"
	"runtime/debug"
	"time"
)

// 内存策略只做两件事，而且都做得保守：
//   - 启动时给 Go 一个软上限，避免异常情况把内存吃穿（GOGC 保持默认 100，
//     降 GC 百分比换来的是更频繁的 GC，与「省 CPU」的目标相悖）；
//   - 只有在「藏进托盘 ≥30 秒，而且这段时间没有新流量」时才修剪一次工作集。
//
// 修剪（FreeOSMemory / SetProcessWorkingSetSize）会把页面换出去，
// 下次唤醒要重新缺页读回来；隐藏一两秒就做，等于给自己制造卡顿。
const (
	// memoryLimitBytes 是 Go runtime 的软内存上限。
	memoryLimitBytes = 384 << 20
	// trimHiddenFor 是「藏得够久」的阈值。
	trimHiddenFor = 30 * time.Second
	// trimIdleFor 是「没有流量」的阈值。
	trimIdleFor = 30 * time.Second
)

// shouldTrim 决定这次隐藏期间要不要修剪工作集。
func shouldTrim(hiddenFor, idleFor time.Duration) bool {
	return hiddenFor >= trimHiddenFor && idleFor >= trimIdleFor
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
	total := a.trafficTotal()
	if total != a.trafficMark {
		a.trafficMark = total
		a.lastTrafficAt = time.Now()
	}
}

// maybeTrimMemory 在状态 ticker 里调：满足条件才修剪，一次隐藏只修一次。
func (a *app) maybeTrimMemory() {
	if !a.windowHidden.Load() || a.hiddenSince.IsZero() || a.trimmedThisHide {
		return
	}
	hiddenFor := time.Since(a.hiddenSince)
	// lastTrafficAt 为零值时表示「一直没流量」，按够久处理。
	idleFor := time.Duration(1<<62 - 1)
	if !a.lastTrafficAt.IsZero() {
		idleFor = time.Since(a.lastTrafficAt)
	}
	if !shouldTrim(hiddenFor, idleFor) {
		return
	}
	a.trimmedThisHide = true
	a.trimMemory()
}

// trimMemory 是真正的修剪：先让 Go 回收，再让系统把工作集换出去。
func (a *app) trimMemory() {
	if a.trimMemoryFn != nil {
		a.trimMemoryFn()
		return
	}
	runtime.GC()
	debug.FreeOSMemory()
	trimWorkingSet()
	a.tunLogf("窗口已隐藏 %s 且无流量，已修剪工作集", trimHiddenFor)
}
