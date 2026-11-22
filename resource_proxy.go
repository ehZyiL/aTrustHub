package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type captureProxySnapshot struct {
	Enabled  uint64
	Server   string
	Override string
	// Fingerprint 是注册表项的哈希，用来判断“这份设置有没有被动过”。
	Fingerprint string
	// Automatic 是自动代理的总开关：PAC（AutoConfigURL）或自动检测（AutoDetect）开着。
	Automatic bool
	// PAC 单独记“真的配了自动代理脚本”。它与 Automatic 的区别很重要：
	// AutoDetect 在很多机器上默认就开着且不影响手动代理，而 PAC 会接管分流，
	// 属于别人的设置——前者可以忽略，后者不能抢。
	PAC bool
}
type captureProxyRecovery struct{ Before, Installed captureProxySnapshot }
type captureProxyOps struct {
	read       func() (captureProxySnapshot, error)
	setEnabled func(uint64) error
	// setProxy writes the manual proxy address and its bypass list. Only the
	// system-proxy journal needs it; the resource-TUN journal never rewrites an
	// address, so it leaves this nil.
	setProxy func(server, override string) error
	notice   func(string)
}

// ownsProxy 判断这份手动代理设置是不是指向 address——也就是“这一份是我们的”。
//
// 它只看本应用实际写入的两项：ProxyEnable 与 ProxyServer。自动检测（AutoDetect）
// 与 PAC（AutoConfigURL）不参与：本应用从不写这两项。把 AutoDetect 算进来会让
// 自动接管在开着“自动检测设置”的机器上永远开不起来（日志里表现为“已被其他软件
// 设置”），而且手动开完几分钟内又会被当成丢失去关掉。
//
// PAC 另算：它意味着别人的分流在生效，自动接管时不去抢——那条判断在
// proxyForeignReason 里，不影响“这份手动代理是不是我们写的”。
func ownsProxy(snapshot captureProxySnapshot, address string) bool {
	return snapshot.Enabled != 0 && (snapshot.Server == "socks="+address || snapshot.Server == address)
}

// proxyForeignReason 说明“自动接管为什么不能动这份设置”，空字符串表示能动。
// 它只做决策，不碰平台：Windows 侧把它接到注册表，其它平台拿读到的零快照也能用。
func proxyForeignReason(snapshot captureProxySnapshot, address string) string {
	switch {
	case snapshot.PAC:
		// PAC 会接管分流：即使手动代理那一栏是我们的，也不去盖掉别人的策略。
		return "配置了自动代理脚本（PAC），不覆盖"
	case snapshot.Enabled == 0:
		return ""
	case !ownsProxy(snapshot, address):
		return "ProxyEnable=1，ProxyServer=" + snapshot.Server
	}
	return ""
}

// sameRegistryState 比较“注册表里真正被本应用写过的那几项”。
//
// 它刻意不比较 PAC/Automatic 这类描述字段：恢复记录可能是旧版本写的（那时还没有
// PAC 字段），字段一变就把“没人动过”误判成“外部修改”，TUN 会因此起不来。
// Fingerprint 已经盖了 ProxyServer/ProxyOverride/AutoConfigURL/AutoDetect，但不含
// ProxyEnable（切换时它会变），所以 Enable 得单独比。
func (s captureProxySnapshot) sameRegistryState(other captureProxySnapshot) bool {
	return s.Enabled == other.Enabled && s.Server == other.Server &&
		s.Override == other.Override && s.Fingerprint == other.Fingerprint
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
	if !current.sameRegistryState(installed) {
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
		if !current.sameRegistryState(record.Before) {
			if !current.sameRegistryState(record.Installed) {
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
