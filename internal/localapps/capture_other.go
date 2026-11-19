//go:build !linux

package localapps

import (
	"context"
	"errors"
	"github.com/qy/easyconnect/internal/model"
)

func startCapture(context.Context, model.LocalApp, DialFunc) (managedCapture, error) {
	return nil, errors.New("软件 TCP 接管目前仅在 Linux 实验版提供")
}
