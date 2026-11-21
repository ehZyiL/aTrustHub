//go:build linux

package main

import (
	"context"

	"github.com/ehzyil/connect-hub/internal/capture"
)

// Linux has a persistent helper service, so restoring app capture does not
// require an interactive authentication prompt.
func supportsAutoRestoreAppCapture() (bool, string) {
	return true, ""
}

func autoCaptureHelperReady(ctx context.Context) error {
	return capture.HelperAvailable(ctx)
}
