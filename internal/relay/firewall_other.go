//go:build !windows

package relay

import (
	"errors"
	"runtime"
)

// FirewallInfo gives platform guidance without pretending one button fixes every
// firewall. Only Windows ships an automatic minimal rule in this version.
func FirewallInfo() FirewallGuidance {
	switch runtime.GOOS {
	case "darwin":
		return FirewallGuidance{
			Platform: "macos",
			Lines: []string{
				"macOS 的应用防火墙可能询问是否允许本程序接受传入连接；请在系统设置中确认。",
				"首版不自动修改系统防火墙，请按系统提示操作。",
			},
		}
	case "linux":
		return FirewallGuidance{
			Platform: "linux",
			Lines: []string{
				"Linux 发行版的防火墙各不相同（firewalld、ufw、nftables）。",
				"需要放行时请只允许本机当前分享端口，并限定来源网段；本程序不会自行修改规则。",
			},
		}
	default:
		return FirewallGuidance{Platform: runtime.GOOS, Lines: []string{
			"当前平台没有内置的防火墙操作，请按系统文档放行分享端口。",
		}}
	}
}

// ApplyFirewallRule is unavailable outside Windows in this version.
func ApplyFirewallRule(rule FirewallRule) error {
	return errors.New("当前平台不支持自动创建防火墙规则，请按提示手动放行")
}

// RemoveFirewallRule is unavailable outside Windows in this version.
func RemoveFirewallRule(id string) error {
	return errors.New("当前平台没有本程序创建的防火墙规则")
}
