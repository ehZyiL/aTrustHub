//go:build !windows

package main

import "github.com/egoist/mygo/ui"

func supportsCleanup() bool {
	return false
}

type cleanupState struct{}

func (a *app) maintenanceSection(c *ui.Context) {}
