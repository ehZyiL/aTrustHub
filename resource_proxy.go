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
	if before.Automatic {
		return nil, errors.New("系统使用自动代理配置，请先关闭自动代理再启用系统 TUN")
	}
	if before.Enabled == 0 {
		return func() error { return nil }, nil
	}
	if before.Server != "socks="+address && before.Server != address {
		return nil, errors.New("当前系统代理由其他配置管理，请先关闭它再启用系统 TUN")
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
