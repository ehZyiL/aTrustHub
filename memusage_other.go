//go:build !linux && !windows

package main

// residentBytes 在不支持读取常驻内存的平台上返回 0，修剪日志退回不带数字版本。
func residentBytes() int64 { return 0 }
