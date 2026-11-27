//go:build !windows && !linux

package desktop

// supportsQuitOnClosePlatform 在 macOS 及其它平台隐藏该开关：
// macOS 的关窗是隐藏，退出走菜单，不需要它。
func supportsQuitOnClosePlatform() bool { return false }
