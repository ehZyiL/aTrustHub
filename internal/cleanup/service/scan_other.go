//go:build !windows

package service

import (
	"context"
	"errors"
)

var ErrUnsupported = errors.New("sangfor cleanup is only supported on Windows")

type ScanOptions struct {
	ForceElevateCheck bool
	Context           context.Context
}

func Scan(opts ScanOptions) (*Plan, error) {
	return nil, ErrUnsupported
}
