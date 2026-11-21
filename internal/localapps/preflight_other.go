//go:build !linux && !windows

package localapps

import (
	"context"

	"github.com/ehZyiL/connect-hub/internal/model"
)

// The platform launcher reports unsupported capture on these platforms.
func checkCaptureProgram(ctx context.Context, _ model.LocalApp) error { return ctx.Err() }
