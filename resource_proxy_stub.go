//go:build !windows

package main

import "errors"

func suspendProxyForResourceTUN(string, string) (func() error, error) {
	return nil, errors.New("当前平台尚未提供系统 TCP 接管")
}
func recoverResourceProxy(string, string) error { return nil }
