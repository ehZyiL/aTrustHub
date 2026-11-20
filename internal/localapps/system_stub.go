//go:build !windows && !linux

package localapps

import (
	"context"
	"errors"
)

func (m *Manager) StartSystemCapture(context.Context, []CaptureConfig, DialFunc) (SystemCapture, error) {
	return nil, errors.New("当前平台尚未实现系统 TCP 接管")
}
