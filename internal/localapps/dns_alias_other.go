//go:build !linux && !windows

package localapps

import (
	"context"
	"errors"
)

func prepareMappedDNS(context.Context, string, CaptureConfig) (aliasBinding, error) {
	return nil, errors.New("当前平台尚未支持按软件域名映射")
}
