//go:build linux

package desktop

import (
	"errors"
	"syscall"
)

// The first Linux release serves application proxies. System networking is
// enabled only after a Linux helper with owned-rule recovery is implemented.
var errLinuxHelperUnavailable = errors.New("Linux 的全局 TUN 尚未启用，请用「应用接管」或代理浏览器/软件的 SOCKS/HTTP 设置")

func supportsSystemProxy() bool                             { return false }
func supportsElevatedTUN() bool                             { return false }
func supportsAutoSystemProxy() bool                         { return false }
func startHelper(string, []string, string) error            { return errLinuxHelperUnavailable }
func startHelperElevated(string, []string, string) error    { return errLinuxHelperUnavailable }
func (a *app) ensureHelperPrivilege(string, []string) error { return errLinuxHelperUnavailable }

// This application has not changed Linux DNS, so there is nothing to restore.
func (a *app) cleanupStaleDNS() {}
func terminateHelper(int) error { return errLinuxHelperUnavailable }
func helperAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
