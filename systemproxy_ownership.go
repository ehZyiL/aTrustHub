package main

import (
	"net"
	"runtime"
	"strconv"
)

var systemProxyOwnedFn = systemProxyOwned

// systemProxyForeignFn is the seam tests use: unit tests must never read the
// machine's real proxy settings.
var systemProxyForeignFn = systemProxyForeign

// systemProxyAddress is the loopback endpoint of the aggregate listener. It is
// read from the 3-second ticker, so it must not touch a.cfg without the lock.
func (a *app) systemProxyAddress() string {
	a.cfgMu.RLock()
	port := a.cfg.Settings.AggregatePort
	a.cfgMu.RUnlock()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// Windows exposes one shared system proxy. Another application can replace
// it at any time; a cached toggle never grants ownership of the new setting.
func (a *app) releaseLostSystemProxy() bool {
	if runtime.GOOS != "windows" || !a.sysProxyOn.Load() || systemProxyOwnedFn(a.systemProxyAddress()) {
		return false
	}
	// Still our own value, just at the address of a previous configuration (the
	// aggregate port was changed). That is not a third party, and leaving the
	// registry on a dead port would cut the machine off: re-point it instead.
	if address, ok := systemProxyJournalInstalled(a.dir); ok && systemProxyOwnedFn(address) {
		if err := applySystemProxyFn(a.systemProxyAddress(), true); err == nil {
			return false
		}
	}
	a.sysProxyOn.Store(false)
	a.sysProxySwitch.Store(false)
	if a.bus != nil {
		a.bus.Add("app", "系统代理已由其他软件修改或关闭，本应用已停止管理该设置")
	}
	a.invalidateCoalesced()
	return true
}
