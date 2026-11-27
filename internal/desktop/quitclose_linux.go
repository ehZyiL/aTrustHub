//go:build linux

package desktop

// supportsQuitOnClosePlatform 在 Linux 上也提供这个开关：托盘可用时，关窗默认
// 藏进托盘；勾了它才退出。托盘真不可用时开关会被 quitOnCloseSupported 隐藏，
// 关窗按「直接退出」处理（见 closeActionFor）。
func supportsQuitOnClosePlatform() bool { return true }
