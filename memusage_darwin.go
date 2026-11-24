//go:build darwin

package main

import "syscall"

// residentBytes 在 macOS (Darwin) 上调用 syscall.Getrusage 读取当前进程的物理内存常驻集。
// Darwin 内核中 ru_maxrss 的单位是字节 (bytes)。
func residentBytes() int64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err == nil && usage.Maxrss > 0 {
		return usage.Maxrss
	}
	return 0
}
