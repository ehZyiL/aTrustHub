//go:build windows

package main

import "syscall"

// trimWorkingSet 让 Windows 把本进程的物理工作集换出去。参数传
// SIZE_T(-1) 是官方文档里「尽量裁剪」的写法：任务管理器里的内存会明显下降，
// 代价是下次访问这些页时一次缺页读回，所以只在隐藏够久且无流量时调用。
func trimWorkingSet() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("SetProcessWorkingSetSize")
	handle, err := syscall.GetCurrentProcess()
	if err != nil || handle == 0 {
		return
	}
	_, _, _ = proc.Call(uintptr(handle), ^uintptr(0), ^uintptr(0))
}
