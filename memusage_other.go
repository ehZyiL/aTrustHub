//go:build !linux

package main

// residentBytes 只在 Linux 上读 /proc；其它平台返回 0，修剪日志不带数字。
// （Windows 的 SetProcessWorkingSetSize 效果由任务管理器直接可见，这里不另读。）
func residentBytes() int64 { return 0 }
