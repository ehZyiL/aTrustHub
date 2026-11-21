package main

import (
	"time"
)

// 状态机与重绘彻底分开：TUN / 代理 / 本机项目这些业务推进由后台
// ticker 负责，窗口藏进托盘或最小化也照跑；重绘只决定「要不要画」。
//
// 之前这些推进挂在 invalidate() 上，导致「藏起来不画」就顺带把状态机也停了，
// 而「一有事件就画」又把状态推进和整树重建绑在一起。

// startStateTicker 每秒推进一次轻量的状态维护。
// 重活（reconcileLocalApps / checkTunnels / guardSystemProxy / DNS 自检）
// 仍在原来的 3 秒巡检里，这里只放必须及时响应的部分。
func (a *app) startStateTicker() {
	for range time.Tick(time.Second) {
		a.maintainState()
	}
}

// maintainState 是一次状态维护：恢复/刷新 TUN，并记一笔流量，
// 供「不在前台够久且没有流量」时修剪工作集用。它不画界面。
func (a *app) maintainState() {
	a.maybeResumeTUN()
	a.maybeRefreshTUN()
	a.noteTraffic()
	a.maybeTrimMemory()
}

// hideToTray 是关闭按钮的默认行为：藏到托盘，启动门控与降占用。
func (a *app) hideToTray() {
	if a.win == nil {
		return
	}
	a.win.Hide()
	a.updateDockVisibility(true)
	a.windowHidden.Store(true)
	a.idle.begin(time.Now())
}

// showFromTray 把窗口拉回来：清掉隐藏标记并立刻补一帧，
// 因为立即模式界面的点击热区来自上一帧。
func (a *app) showFromTray() {
	a.windowHidden.Store(false)
	a.idle.end()
	// 从托盘叫回时，即使底层窗口还处在最小化，也按「回到前台」处理。
	a.minimized.Store(false)
	if a.win == nil || a.win.IsDestroyed() {
		return
	}
	a.updateDockVisibility(false)
	a.win.Show()
	a.win.Focus()
	a.invalidate()
	// 有些平台在 Show 之后还要一帧才能量出真实尺寸，再补一帧。
	go func() {
		time.Sleep(120 * time.Millisecond)
		if a.win != nil && !a.win.IsDestroyed() && a.windowVisible() {
			a.invalidate()
		}
	}()
}

// syncWindowVisible 在主线程上用框架的 IsVisible() 校正一次门控标记。
// 不直接在每个事件源里查 IsVisible：那是 onMain 同步调用，
// 事件循环退出后会一直等，热路径上也不该做线程往返。
// 最小化的窗口 IsVisible() 仍为 true，所以这条校正不能碰最小化标记。
func (a *app) syncWindowVisible() {
	if a.win == nil {
		return
	}
	if gateClears(a.win.IsVisible(), a.minimized.Load()) && a.windowHidden.Load() {
		a.windowHidden.Store(false)
		a.idle.end()
	}
}

// gateClears 是「托盘隐藏标记能不能清」的纯判定：窗口真的可见，
// 而且不是最小化状态。
func gateClears(isVisible, minimized bool) bool {
	return isVisible && !minimized
}

// onWindowMinimized 是最小化时的降占用：停止重绘，并允许一次工作集修剪。
// Linux 没有托盘，最小化到任务栏就是那里的「后台常驻」。
func (a *app) onWindowMinimized() {
	a.minimized.Store(true)
	a.idle.begin(time.Now())
}

// onWindowRestored 是还原时的补帧：立即模式界面的点击热区来自上一帧。
func (a *app) onWindowRestored() {
	a.minimized.Store(false)
	a.idle.end()
	a.invalidate()
}
