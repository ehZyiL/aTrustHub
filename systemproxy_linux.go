//go:build linux

package main

func systemProxyEnabled() bool            { return false }
func applySystemProxy(string, bool) error { return errLinuxHelperUnavailable }

var applySystemProxyFn = applySystemProxy
