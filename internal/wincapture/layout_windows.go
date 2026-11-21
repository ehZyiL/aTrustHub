package wincapture

import (
	"os"
	"path/filepath"
	"strings"
)

// coreDir keeps the internal programs out of the user-facing top level of the
// portable bundle, so opening the folder does not invite a double-click on an
// executable that can only run as a child of the desktop app.
const coreDir = "core"

// bundleRoot returns the install directory that holds easyconnect-hub.exe. The
// capture helper may sit next to the app (development builds, bundles from
// before the core/ split) or inside core/.
func bundleRoot(exe string) string {
	dir := filepath.Dir(exe)
	if strings.EqualFold(filepath.Base(dir), coreDir) {
		return filepath.Dir(dir)
	}
	return dir
}

// helperPath resolves the capture helper from the desktop executable. The
// desktop's own directory is authoritative here, so a bundle extracted into a
// folder that happens to be called "core" cannot confuse the lookup.
// core/ is the shipped layout; the flat location stays supported for
// development build directories and bundles extracted before the split.
func helperPath(exe string) (string, bool) {
	dir := filepath.Dir(exe)
	for _, candidate := range []string{
		filepath.Join(dir, coreDir, "easyconnect-hub-capture.exe"),
		filepath.Join(dir, "easyconnect-hub-capture.exe"),
	} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, true
		}
	}
	return "", false
}
