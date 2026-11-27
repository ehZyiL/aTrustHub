//go:build !linux

package desktop

import (
	"context"
	"errors"
)

// Windows starts its helper through UAC, so an automatic restart would always
// show an administrator prompt. Keep the manual switch only until a
// non-interactive helper lifecycle exists.
func supportsAutoRestoreAppCapture() (bool, string) {
	return false, "当前平台暂不支持自动恢复应用接管（Windows 启动助手需要管理员授权）"
}

func autoCaptureHelperReady(context.Context) error {
	return errors.New("当前平台暂不支持自动恢复应用接管")
}
