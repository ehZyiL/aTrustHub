//go:build !windows

package main

// supportsQuitOnClosePlatform 在非 Windows 平台隐藏该开关。
func supportsQuitOnClosePlatform() bool { return false }
