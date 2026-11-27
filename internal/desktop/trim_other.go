//go:build !windows

package desktop

// trimWorkingSet 在非 Windows 平台什么都不做：macOS/Linux 的页回收策略
// 由内核按压力决定，强行 madvise 出去只会让下次唤醒更慢。
func trimWorkingSet() {}
