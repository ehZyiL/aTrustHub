//go:build windows

package desktop

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// The proxy watchdog is the lightweight answer to "the user killed the app and
// never opens it again": a child of the GUI that waits on the parent's process
// handle and restores the system-proxy journal when it disappears. It needs no
// elevation (HKCU only) and no service: its lifetime is exactly the lifetime of
// the process that wrote the journal.
//
// The parent side lives in systemproxy_windows.go (startProxyWatchdog); this file
// only runs in the child, which must return before anything else starts.
func runProxyWatchdog(args []string) {
	if len(args) != 2 {
		return
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 0 {
		return
	}
	dir := args[1]
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// The GUI is already gone, so its exit path did not finish: restore now.
		restoreSystemProxyAfterDeath(dir)
		return
	}
	defer windows.CloseHandle(parent)
	_, _ = windows.WaitForSingleObject(parent, windows.INFINITE)
	restoreSystemProxyAfterDeath(dir)
}
