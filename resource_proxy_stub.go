//go:build !windows && !linux

package main

import "errors"

func suspendProxyForResourceTUN(string, string, func(string)) (func() error, error) {
	return nil, errors.New("当前平台尚未提供系统 TCP 接管")
}
func recoverResourceProxy(string, string) error { return nil }
func systemProxyOwned(string) bool              { return systemProxyEnabled() }

// systemProxyForeign 在本平台无法判断是否有第三方代理，交由调用方按平台受限。
func systemProxyForeign(string) bool { return false }
