//go:build windows

package relay

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// FirewallInfo describes what this build offers on Windows: one explicit,
// minimal inbound rule the user must trigger, with elevation.
func FirewallInfo() FirewallGuidance {
	return FirewallGuidance{
		Platform:  "windows",
		Automatic: true,
		Lines: []string{
			"Windows 防火墙可能拦截局域网入站连接。",
			"「允许局域网连接」只创建一条本程序、当前端口、专用网络、所选局域网范围的最小规则，需要系统授权。",
			"取消系统授权不会修改任何既有规则，分享保持原状。",
		},
	}
}

// ApplyFirewallRule creates the rule and reads it back. It requires elevation and
// never runs on its own: the user must ask for it.
func ApplyFirewallRule(rule FirewallRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + rule.ID,
		"dir=in",
		"action=allow",
		"program=" + rule.ProgramPath,
		"protocol=TCP",
		fmt.Sprintf("localport=%d", rule.Port),
		"profile=" + rule.Profile,
	}
	if rule.RemoteIP != "" {
		args = append(args, "remoteip="+rule.RemoteIP)
	}
	if out, err := exec.Command("netsh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("创建防火墙规则失败：%v（%s）", err, strings.TrimSpace(string(out)))
	}
	if !firewallRuleExists(rule.ID) {
		return errors.New("防火墙规则创建后读不到，未确认生效")
	}
	return nil
}

// RemoveFirewallRule deletes only our own rule and confirms it is gone.
func RemoveFirewallRule(id string) error {
	if !strings.HasPrefix(id, "ConnectHub-LANShare-") {
		return errors.New("拒绝删除非本程序创建的防火墙规则")
	}
	if _, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+id).CombinedOutput(); err != nil {
		return fmt.Errorf("删除防火墙规则失败：%w", err)
	}
	if firewallRuleExists(id) {
		return errors.New("防火墙规则仍然存在，清理未完成")
	}
	return nil
}

func firewallRuleExists(id string) bool {
	out, err := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+id).CombinedOutput()
	return err == nil && strings.Contains(string(out), id)
}
