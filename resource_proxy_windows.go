package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func captureProxyRegistryOps() captureProxyOps {
	const keyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	return captureProxyOps{
		read: func() (captureProxySnapshot, error) {
			key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return captureProxySnapshot{}, nil
			}
			if err != nil {
				return captureProxySnapshot{}, err
			}
			defer key.Close()
			snapshot := captureProxySnapshot{}
			snapshot.Enabled, _, err = key.GetIntegerValue("ProxyEnable")
			if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return snapshot, err
			}
			values := map[string]any{}
			for _, name := range []string{"ProxyServer", "ProxyOverride", "AutoConfigURL"} {
				value, kind, err := key.GetStringValue(name)
				if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
					return snapshot, err
				}
				values[name] = []any{value, kind, err == nil}
				if name == "ProxyServer" {
					snapshot.Server = value
				}
				if name == "AutoConfigURL" && value != "" {
					snapshot.Automatic = true
				}
			}
			auto, kind, err := key.GetIntegerValue("AutoDetect")
			if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return snapshot, err
			}
			values["AutoDetect"] = []any{auto, kind, err == nil}
			snapshot.Automatic = snapshot.Automatic || auto != 0
			data, _ := json.Marshal(values)
			hash := sha256.Sum256(data)
			snapshot.Fingerprint = hex.EncodeToString(hash[:])
			return snapshot, nil
		}, setEnabled: func(value uint64) error {
			key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
			if err != nil {
				return err
			}
			defer key.Close()
			if err := key.SetDWordValue("ProxyEnable", uint32(value)); err != nil {
				return err
			}
			notifyProxyChanged()
			return nil
		},
	}
}

func suspendProxyForResourceTUN(dir, address string, notice func(string)) (func() error, error) {
	ops := captureProxyRegistryOps()
	ops.notice = notice
	return suspendOwnedProxy(filepath.Join(dir, "system-tun-proxy-recovery.json"), address, ops)
}

func systemProxyOwned(address string) bool {
	snapshot, err := captureProxyRegistryOps().read()
	return err == nil && ownsProxy(snapshot, address)
}

func recoverResourceProxy(dir, address string) error {
	path := filepath.Join(dir, "system-tun-proxy-recovery.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var record captureProxyRecovery
	if len(data) > 16384 || json.Unmarshal(data, &record) != nil || record.Before.Enabled != 1 || record.Installed.Enabled != 0 || record.Before.Fingerprint != record.Installed.Fingerprint {
		return errors.New("系统 TUN 代理恢复记录无效")
	}
	if record.Before.Server != "socks="+address && record.Before.Server != address {
		return errors.New("旧代理入口已改变，保留关闭状态，请在界面选择代理模式")
	}
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return errors.New("旧代理入口尚未监听，保留关闭状态")
	}
	conn.Close()
	return restoreOwnedProxy(path, record, captureProxyRegistryOps())()
}
