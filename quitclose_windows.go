//go:build windows

package main

// supportsQuitOnClosePlatform 只在 Windows 上提供这个开关：
// Linux 一直是关窗即退出，macOS 的关窗是隐藏，两边都不需要它。
func supportsQuitOnClosePlatform() bool { return true }
