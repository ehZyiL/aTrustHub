//go:build !windows && !darwin

package main

// systemproxy_journal_other.go keeps the other platforms exactly as they were.
// macOS writes the proxy through networksetup per service, and undoing that
// needs its own read/restore implementation verified on a real machine; Linux has
// no system proxy support at all (see platform_linux.go). Until then those
// platforms keep the plain apply/disable behaviour, and the journal stays
// Windows-only.

// recoverSystemProxy is a no-op where nothing is journalled.
func (a *app) recoverSystemProxy() error { return nil }
