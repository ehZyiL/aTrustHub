package main

import (
	"net"
	"runtime"
	"strconv"
)

var systemProxyOwnedFn = systemProxyOwned

func (a *app) systemProxyAddress() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(a.cfg.Settings.AggregatePort))
}

// Windows exposes one shared system proxy. Another application can replace
// it at any time; a cached toggle never grants ownership of the new setting.
func (a *app) releaseLostSystemProxy() bool {
	if runtime.GOOS != "windows" || !a.sysProxyOn || systemProxyOwnedFn(a.systemProxyAddress()) {
		return false
	}
	a.sysProxyOn, a.sysProxySwitch = false, false
	if a.bus != nil {
		a.bus.Add("app", "系统代理已由其他软件修改或关闭，本应用已停止管理该设置")
	}
	if a.win != nil {
		a.win.Invalidate()
	}
	return true
}
