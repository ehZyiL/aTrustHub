package main

import "github.com/ehzyil/connect-hub/internal/vpn"

// 日志是最便宜也最吵的事件源：跑流量时每建一条连接都会写一行。
// 这里决定「什么时候值得为一条日志重绘」，以及渲染多少行。
const (
	// logRenderLimit 是面板里实际排版的行数：60 行足够看清现场，
	// 而 200 行的排版开销是它的三倍多。
	logRenderLimit = 60
	// logCopyLimit 是「复制全部」拿到的行数，比渲染多，便于贴给别人。
	logCopyLimit = 200
)

// logViewsVisible 判断这一帧日志面板是否真的在画：日志需要打开且停在
// 「日志」分区，或者停在访问日志页。只由主线程（view）调用。
func (a *app) logViewsVisible() bool {
	if a.settings.open {
		return a.settings.section == settingLogs && a.logsOpen
	}
	return a.tab == 2
}

// syncLogViewActive 在主线程把判定结果快照进原子量：
// 日志回调跑在 logger 的 goroutine 上，不能直读 settings / tab。
func (a *app) syncLogViewActive() {
	a.logViewActive.Store(a.logViewsVisible())
}

// onLogEvent 是 logbus 的回调。正在看日志就按 30 FPS 合并刷新；
// 其它页面降到 1 秒一次——首屏的「最近的失败」最多慢一秒，不会停更。
func (a *app) onLogEvent() {
	if a.logViewActive.Load() {
		a.invalidateCoalesced()
		return
	}
	a.invalidateLogSlow()
}

// lastEntries 取最近 n 条，用于渲染上限；n<=0 表示不截断。
func lastEntries(entries []vpn.LogEntry, n int) []vpn.LogEntry {
	if n <= 0 || len(entries) <= n {
		return entries
	}
	return entries[len(entries)-n:]
}
