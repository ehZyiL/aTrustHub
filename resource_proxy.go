package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type captureProxySnapshot struct {
	Enabled     uint64
	Server      string
	Fingerprint string
	Automatic   bool
}
type captureProxyRecovery struct{ Before, Installed captureProxySnapshot }
type captureProxyOps struct {
	read       func() (captureProxySnapshot, error)
	setEnabled func(uint64) error
	notice     func(string)
}

func ownsProxy(snapshot captureProxySnapshot, address string) bool {
	return snapshot.Enabled != 0 && !snapshot.Automatic && (snapshot.Server == "socks="+address || snapshot.Server == address)
}

func suspendOwnedProxy(path, address string, ops captureProxyOps) (func() error, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, errors.New("上次系统代理恢复记录尚未处理，请先重试恢复")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	before, err := ops.read()
	if err != nil {
		return nil, err
	}
	if !ownsProxy(before, address) {
		if (before.Enabled != 0 || before.Automatic) && ops.notice != nil {
			ops.notice("系统 TUN 保留第三方系统代理；使用该代理的应用仍遵循其分流规则，内网目标需在该代理中设置绕过或使用本应用统一入口")
		}
		return func() error { return nil }, nil
	}
	installed := before
	installed.Enabled = 0
	record := captureProxyRecovery{Before: before, Installed: installed}
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if err = os.WriteFile(path+".tmp", data, 0600); err != nil {
		return nil, err
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		return nil, err
	}
	restore := restoreOwnedProxy(path, record, ops)
	if err = ops.setEnabled(0); err != nil {
		return restore, err
	}
	current, err := ops.read()
	if err != nil {
		return restore, err
	}
	if current != installed {
		return restore, errors.New("系统代理在模式切换期间发生外部变化")
	}
	return restore, nil
}

func restoreOwnedProxy(path string, record captureProxyRecovery, ops captureProxyOps) func() error {
	var mu sync.Mutex
	complete := false
	return func() error {
		mu.Lock()
		defer mu.Unlock()
		if complete {
			return nil
		}
		current, err := ops.read()
		if err != nil {
			return err
		}
		if current != record.Before {
			if current != record.Installed {
				return errors.New("系统代理已被外部修改，保留当前配置；恢复记录尚未清理")
			}
			if err = ops.setEnabled(record.Before.Enabled); err != nil {
				return err
			}
		}
		if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		complete = true
		return nil
	}
}
