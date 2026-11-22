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

// systemProxyStateFn is the same seam for the one-line description the log
// carries: reading it from a test would reach the real registry too.
var systemProxyStateFn = systemProxyState

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
		// 把实测值写进日志：否则“被其他软件修改或关闭”无法区分是自己被改、
		// 被关掉、还是被另一个程序抢走（常见的两个进程/两个代理软件共存）。
		reason := systemProxyStateFn(a.systemProxyAddress())
		if reason == "" {
			reason = "系统代理不再是本应用的入口"
		}
		a.bus.Add("app", "系统代理已由其他软件修改或关闭（"+reason+"），本应用已停止管理该设置")
		// 同一个原因也要在界面上说一句：代理由开变关，用户第一感受是“网断了”。
		a.setToast("系统代理已被其他软件改回或关闭（" + reason +
			"），本应用已停止管理；需要的话请在「网络与接管」里重新选「系统代理」")
	}
	a.invalidateCoalesced()
	return true
}
