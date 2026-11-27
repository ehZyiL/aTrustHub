//go:build linux

package desktop

func systemProxyEnabled() bool            { return false }
func applySystemProxy(string, bool) error { return errLinuxHelperUnavailable }

var applySystemProxyFn = applySystemProxy
