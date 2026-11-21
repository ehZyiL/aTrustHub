//go:build !windows && !darwin && !linux

package main

// setupTray is a no-op on platforms without a tray.
func (a *app) setupTray() {}

// supportsDockToggle reports whether the Dock icon can be hidden here.
func supportsDockToggle() bool { return false }

// startupTray does nothing outside Windows and Linux.
func (a *app) startupTray() {}

// updateDockVisibility does nothing outside macOS.
func (a *app) updateDockVisibility(hidden bool) {}
