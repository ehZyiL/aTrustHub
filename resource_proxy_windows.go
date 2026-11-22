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
				switch name {
				case "ProxyServer":
					snapshot.Server = value
				case "ProxyOverride":
					snapshot.Override = value
				case "AutoConfigURL":
					if value != "" {
						snapshot.Automatic = true
						snapshot.PAC = true
					}
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

// systemProxyForeign 报告系统代理被别的程序开着（不是我们写的那个入口）。
// 只有手动代理算数：自动检测（AutoDetect）在很多机器上默认就开着，也不妨碍手动
// 代理生效；而 PAC 会接管分流，属于别人的策略，不抢——两者分开在
// proxyForeignReason 里处理。
func systemProxyForeign(address string) bool {
	snapshot, err := captureProxyRegistryOps().read()
	if err != nil {
		return true // 读不到就别动：宁可不开，也不覆盖别人的设置
	}
	return proxyForeignReason(snapshot, address) != ""
}

// systemProxyState 把系统代理的当前实测值拼成一行，给日志用：
// “已被其他软件设置”对排障来说信息量为零，得知道占着的是什么地址。
func systemProxyState(address string) string {
	snapshot, err := captureProxyRegistryOps().read()
	if err != nil {
		return "读不到系统代理设置：" + err.Error()
	}
	if reason := proxyForeignReason(snapshot, address); reason != "" {
		return reason
	}
	if snapshot.Enabled == 0 {
		return "ProxyEnable=0（系统代理已关闭）"
	}
	return "ProxyEnable=1，ProxyServer=" + snapshot.Server + "（本应用入口）"
}

func recoverResourceProxy(dir string) error {
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
	// The address comes from the record itself, so recovery no longer depends on
	// the aggregate listener being configured or up at this moment.
	address := proxyAddressFromServer(record.Installed.Server)
	if address == "" {
		return errors.New("恢复记录缺少原代理入口地址")
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
