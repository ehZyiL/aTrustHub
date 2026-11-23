//go:build !windows

package sangforclean

import (
	"errors"
)

var ErrUnsupported = errors.New("sangfor cleanup is only supported on Windows")

type ScanOptions struct {
	ForceElevateCheck bool
}

func Scan(opts ScanOptions) (*Plan, error) {
	return nil, ErrUnsupported
}
