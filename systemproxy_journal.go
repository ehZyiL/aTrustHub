package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// proxyWatchdogFlag starts the child that restores the system-proxy journal when
// the GUI dies without running its exit path.
const proxyWatchdogFlag = "--proxy-watchdog"

// systemProxyJournalDir enables the transaction log for the system proxy. It is
// set once at startup from the data directory and stays empty in unit tests, so a
// test that replaces applySystemProxyFn can never touch the real registry or
// leave a journal behind.
var systemProxyJournalDir string

func setSystemProxyJournalDir(dir string) { systemProxyJournalDir = dir }

// The system-proxy journal is the same idea as the resource-TUN proxy journal
// (resource_proxy.go), applied to the 系统代理 control: remember what the user
// had before the app pointed the machine at its own loopback listener, and give
// it back on stop, on exit, and after a crash.
//
// It has its own record type on purpose: the resource-TUN journal only toggles
// ProxyEnable and keeps every other value, so it can require
// Before.Fingerprint == Installed.Fingerprint. This one rewrites ProxyServer and
// ProxyOverride, so the two fingerprints necessarily differ.
type systemProxyRecord struct {
	Before    captureProxySnapshot
	Installed captureProxySnapshot
}

// systemProxyJournalPath is the transaction log inside the data directory.
func systemProxyJournalPath(dir string) string {
	return filepath.Join(dir, "system-proxy-recovery.json")
}

// proxyAddressFromServer accepts the two shapes WinINET stores a manual proxy
// in ("socks=host:port" and "host:port") and returns host:port.
func proxyAddressFromServer(server string) string {
	if len(server) > len("socks=") && server[:len("socks=")] == "socks=" {
		return server[len("socks="):]
	}
	return server
}

func writeSystemProxyRecord(path string, record systemProxyRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".system-proxy-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Written and synced before the registry change: a crash can then only leave
	// "recorded but not applied" (harmless, detected on restore) or nothing.
	return os.Rename(name, path)
}

// applySystemProxyJournaled points the machine at hostPort, recording what it
// replaced. It refuses to overwrite an unresolved record: restoring that first
// is the only way to keep the user's original value.
func applySystemProxyJournaled(path, hostPort string, ops captureProxyOps, fallback func(string, bool) error) error {
	server := "socks=" + hostPort
	if _, err := os.Stat(path); err == nil {
		if err := restoreSystemProxyJournaled(path, ops); err != nil {
			switch {
			case errors.Is(err, errProxyOwnedElsewhere):
				// The user is explicitly taking the setting over, so the value in
				// place becomes the new baseline. Keeping the old record would block
				// every future takeover and could never be restored anyway.
				if rerr := discardProxyJournal(path, false); rerr != nil {
					return rerr
				}
			case errors.Is(err, errProxyJournalCorrupt):
				if rerr := discardProxyJournal(path, true); rerr != nil {
					return rerr
				}
			default:
				return fmt.Errorf("上次的系统代理恢复未完成：%w", err)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	before, err := ops.read()
	if err != nil {
		return err
	}
	if ownsProxy(before, hostPort) {
		// Already pointing at this listener: nothing to record, just make sure it
		// is enabled.
		if fallback == nil {
			return ops.setEnabled(1)
		}
		return fallback(hostPort, true)
	}
	if ops.setProxy == nil {
		// No way to write the address on this platform: keep the old behaviour
		// instead of pretending to journal it.
		if fallback == nil {
			return errors.New("当前平台不支持写入系统代理")
		}
		return fallback(hostPort, true)
	}
	installed := before
	installed.Enabled = 1
	installed.Server = server
	installed.Override = "<local>"
	installed.Automatic = false
	// The fingerprint of the installed state is not used for comparison; it is
	// recomputed by ops.read after the write.
	installed.Fingerprint = ""
	record := systemProxyRecord{Before: before, Installed: installed}
	if err := writeSystemProxyRecord(path, record); err != nil {
		return err
	}
	if err := ops.setProxy(server, "<local>"); err != nil {
		return err
	}
	if err := ops.setEnabled(1); err != nil {
		return err
	}
	now, err := ops.read()
	if err != nil {
		return err
	}
	if !ownsProxy(now, hostPort) {
		return errors.New("系统代理写入后校验失败，恢复记录已保留")
	}
	return nil
}

// systemProxyJournalInstalled reports the address this app last installed, so a
// changed configuration can be told apart from a third party taking the setting
// over. Both are "the registry no longer matches the configured port", but only
// one of them may be repaired automatically.
func systemProxyJournalInstalled(dir string) (string, bool) {
	if dir == "" {
		return "", false
	}
	data, err := os.ReadFile(systemProxyJournalPath(dir))
	if err != nil {
		return "", false
	}
	var record systemProxyRecord
	if json.Unmarshal(data, &record) != nil {
		return "", false
	}
	address := proxyAddressFromServer(record.Installed.Server)
	if address == "" {
		return "", false
	}
	return address, true
}

// errProxyOwnedElsewhere means the setting now belongs to another program, so the
// record can never be restored without overwriting someone else's value. It is a
// distinct error because the caller may then drop the record instead of leaving a
// takeover that can never succeed again.
var errProxyOwnedElsewhere = errors.New("系统代理已被其他程序修改")

// errProxyJournalCorrupt means the record cannot be parsed. Startup keeps it for
// inspection; an explicit takeover moves it aside instead of blocking forever.
var errProxyJournalCorrupt = errors.New("系统代理恢复记录无效")

// discardProxyJournal removes a record that can no longer be applied. Evidence of
// a corrupt one is renamed instead of deleted, so a bug report still has it.
func discardProxyJournal(path string, corrupt bool) error {
	if corrupt {
		if err := os.Rename(path, path+".broken"); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// releaseSystemProxyJournal resolves the record when the proxy is being switched
// off. disable=true means the caller should perform the plain "switch it off"
// write because nothing of ours is recorded; disable=false means the setting was
// restored, or was already someone else's and must be left alone.
func releaseSystemProxyJournal(path string, ops captureProxyOps) (disable bool, err error) {
	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return true, nil
	} else if statErr != nil {
		return false, statErr
	}
	err = restoreSystemProxyJournaled(path, ops)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, errProxyOwnedElsewhere):
		// Nothing of ours is in the setting any more, and the value in place
		// belongs to another program: leave it untouched and drop the record,
		// which could never be restored without overwriting them.
		return false, discardProxyJournal(path, false)
	case errors.Is(err, errProxyJournalCorrupt):
		// Keep the evidence and do not touch the registry; an explicit takeover
		// moves it aside later.
		return false, nil
	default:
		// A real failure (I/O, verification): the caller still switches our value
		// off so the machine keeps a working network, and the record stays for the
		// next attempt.
		return true, err
	}
}

// restoreSystemProxyJournaled puts the recorded value back. Three outcomes:
//
//	record.Before still in place  → nothing of ours remains, drop the record
//	record.Installed in place     → write Before back, verify, drop the record
//	something else in place       → keep the record and report it, because the
//	                                user or another program owns the value now
func restoreSystemProxyJournaled(path string, ops captureProxyOps) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var record systemProxyRecord
	if len(data) > 16384 || json.Unmarshal(data, &record) != nil {
		return errProxyJournalCorrupt
	}
	current, err := ops.read()
	if err != nil {
		return err
	}
	switch {
	case current.Server == record.Before.Server && current.Enabled == record.Before.Enabled:
		return os.Remove(path)
	case record.Installed.Server != "" && current.Server == record.Installed.Server && current.Enabled != 0:
		if ops.setProxy == nil {
			return errors.New("当前平台无法恢复原代理地址")
		}
		if err := ops.setProxy(record.Before.Server, record.Before.Override); err != nil {
			return err
		}
		if err := ops.setEnabled(record.Before.Enabled); err != nil {
			return err
		}
		now, err := ops.read()
		if err != nil {
			return err
		}
		if now.Server != record.Before.Server || now.Enabled != record.Before.Enabled {
			return errors.New("系统代理恢复后校验失败，记录保留待下次重试")
		}
		return os.Remove(path)
	default:
		return fmt.Errorf("%w：当前为 %q，保留当前设置并留着恢复记录", errProxyOwnedElsewhere, current.Server)
	}
}
