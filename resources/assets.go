// Package resources contains assets shared by the desktop entry point and UI.
package resources

import _ "embed"

// IconPNG is the application icon embedded in the Hub binary.
//
//go:embed icon.png
var IconPNG []byte
