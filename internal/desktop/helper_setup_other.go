//go:build !linux && !windows

package desktop

import "github.com/egoist/mygo/ui"

type platformCaptureSetup struct{}

func (a *app) captureSetupView(*ui.Context) {}
func (a *app) captureSetupBusy() bool       { return false }
func (a *app) closeCaptureSetup()           {}
