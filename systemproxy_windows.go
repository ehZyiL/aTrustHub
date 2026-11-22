//go:build windows

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

// proxyKey is the WinINET settings key every Windows app reads.
const proxyKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// internetSettingsKey is the same key in the form the registry package wants.
const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// proxyWatchdogOnce keeps exactly one child process watching the journal.
var proxyWatchdogOnce sync.Once

// applySystemProxy turns the Windows system proxy (WinINET) on or off, pointing
// it at hostPort. When a journal directory is configured it first remembers what
// it replaces and gives that back when switched off, so the user's own proxy is
// not lost. No elevation is needed: the setting lives in the current user's
// registry.
func applySystemProxy(hostPort string, on bool) error {
	if systemProxyJournalDir == "" {
		return applySystemProxyDirect(hostPort, on)
	}
	ops := systemProxyJournalOps()
	path := systemProxyJournalPath(systemProxyJournalDir)
	if !on {
		disable, err := releaseSystemProxyJournal(path, ops)
		if err != nil {
			// Still switch ours off so the machine keeps a working network.
			if derr := applySystemProxyDirect("127.0.0.1:0", false); derr != nil {
				return fmt.Errorf("%v；另外关闭系统代理也失败：%w", err, derr)
			}
			return err
		}
		if !disable {
			// Either the user's own value is back, or the setting belongs to another
			// program and must not be touched.
			return nil
		}
		return applySystemProxyDirect(hostPort, false)
	}
	if err := applySystemProxyJournaled(path, hostPort, ops, applySystemProxyDirect); err != nil {
		return err
	}
	// The record is on disk and the proxy is ours: make sure someone restores it
	// even if this process is killed rather than closed.
	startProxyWatchdog()
	return nil
}

// applySystemProxyDirect is the plain registry write, with no journal.
func applySystemProxyDirect(hostPort string, on bool) error {
	host, port, ok := strings.Cut(hostPort, ":")
	if !ok || host == "" || port == "" {
		return fmt.Errorf("代理地址无效：%s", hostPort)
	}
	if on {
		// WinINET takes a SOCKS entry as "socks=host:port".
		if out, err := newCmd("reg", "add", proxyKey, "/v", "ProxyServer",
			"/t", "REG_SZ", "/d", "socks="+hostPort, "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("写代理地址失败：%v：%s", err, strings.TrimSpace(string(out)))
		}
		if out, err := newCmd("reg", "add", proxyKey, "/v", "ProxyOverride",
			"/t", "REG_SZ", "/d", "<local>", "/f").CombinedOutput(); err != nil {
			return fmt.Errorf("写代理例外失败：%v：%s", err, strings.TrimSpace(string(out)))
		}
	}
	value := "0"
	if on {
		value = "1"
	}
	if out, err := newCmd("reg", "add", proxyKey, "/v", "ProxyEnable",
		"/t", "REG_DWORD", "/d", value, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("切换代理开关失败：%v：%s", err, strings.TrimSpace(string(out)))
	}
	notifyProxyChanged()
	return nil
}

// systemProxyEnabled reports whether WinINET currently has a proxy enabled.
func systemProxyEnabled() bool {
	out, err := newCmd("reg", "query", proxyKey, "/v", "ProxyEnable").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "0x1")
}

// notifyProxyChanged tells running applications to re-read the settings.
func notifyProxyChanged() {
	const script = `
$sig = '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);'
$t = Add-Type -MemberDefinition $sig -Name WinINet -Namespace Native -PassThru
[void]$t::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
[void]$t::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
`
	_ = newCmd("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).Run()
}

// applySystemProxyFn is the seam tests use, so a unit test never rewrites the
// machine's real proxy settings. Everything in the app must go through it.
var applySystemProxyFn = applySystemProxy

// systemProxyJournalOps adds the "write the address" operation the journal needs
// to the read/enable pair the resource-TUN journal already uses.
func systemProxyJournalOps() captureProxyOps {
	ops := captureProxyRegistryOps()
	ops.setProxy = func(server, override string) error {
		key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer key.Close()
		if err := key.SetStringValue("ProxyServer", server); err != nil {
			return err
		}
		if err := key.SetStringValue("ProxyOverride", override); err != nil {
			return err
		}
		notifyProxyChanged()
		return nil
	}
	return ops
}

// recoverSystemProxy resolves a record left behind by a crash or a failed stop.
// It runs at startup before the app decides whether it currently owns the system
// proxy, and it needs nothing from the aggregate listener: the recorded address
// is read from the record itself.
func (a *app) recoverSystemProxy() error {
	if a.dir == "" {
		return nil
	}
	return restoreSystemProxyJournaled(systemProxyJournalPath(a.dir), systemProxyJournalOps())
}

// startProxyWatchdog launches the child that waits on this process and restores
// the journal if the app is killed instead of closed. One child per run.
func startProxyWatchdog() {
	proxyWatchdogOnce.Do(func() {
		if systemProxyJournalDir == "" {
			return
		}
		exe, err := os.Executable()
		if err != nil {
			return
		}
		// newCmd sets HideWindow; an absolute path passes systemPath unchanged.
		cmd := newCmd(exe, proxyWatchdogFlag, strconv.Itoa(os.Getpid()), systemProxyJournalDir)
		if err := cmd.Start(); err != nil {
			return
		}
		// Reap it so a finished watchdog never lingers as a zombie.
		go func() { _ = cmd.Wait() }()
	})
}

func restoreSystemProxyAfterDeath(dir string) {
	path := systemProxyJournalPath(dir)
	ops := systemProxyJournalOps()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := restoreSystemProxyJournaled(path, ops)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			// Leave the record: the next launch retries and the settings page can
			// show it. Retrying forever would fight whoever changed the value.
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}
