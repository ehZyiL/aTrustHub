//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/relay"
)

// lanShareFirewallView offers the one explicit firewall action this build knows:
// a minimal inbound rule for this program and the current share port. It is
// never applied automatically; enabling a share only shows the guidance.
func (a *app) lanShareFirewallView(c *ui.Context, view relay.View) {
	if view.State != relay.StateRunning {
		return
	}
	t := c.Theme()
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		ui.Text(c, "防火墙恢复记录无法读取："+err.Error()).FontSize(11).TextColor(t.Danger).Wrap()
		return
	}
	present := false
	for _, rule := range journal.Rules {
		if rule.Port == view.Port {
			present = true
		}
	}
	if present {
		ui.Text(c, fmt.Sprintf("已记录本程序端口 %d 的放行规则。", view.Port)).FontSize(11).TextColor(t.TextMuted).Wrap()
	}
	ui.Row(c).Gap(8).Children(func() {
		label := "允许局域网连接"
		if present {
			label = "重新确认放行规则"
		}
		if ui.Button(c, label).FontSize(11).Disabled(a.firewallBusy).Clicked() {
			a.allowLanShareFirewall(view)
		}
		if present && ui.Button(c, "移除放行规则").FontSize(11).Clicked() {
			a.removeLanShareFirewall(view.Port)
		}
	})
	if a.firewallNotice != "" {
		ui.Text(c, a.firewallNotice).FontSize(11).TextColor(t.TextMuted).Wrap()
	}
	if a.firewallErr != "" {
		ui.Text(c, a.firewallErr).FontSize(11).TextColor(t.Danger).Wrap()
	}
}

// allowLanShareFirewall writes the recovery record first, then asks the system to
// create the rule and reads it back. A cancelled elevation leaves the record
// pending and reports it, instead of claiming the port is open.
func (a *app) allowLanShareFirewall(view relay.View) {
	exe, err := os.Executable()
	if err != nil {
		a.firewallErr = "无法确定程序路径：" + err.Error()
		return
	}
	rule := relay.FirewallRule{
		ID:          relay.NewFirewallRuleID(view.Port, time.Now()),
		Name:        "Connect Hub 局域网分享",
		ProgramPath: exe,
		Port:        view.Port,
		Profile:     "private",
		RemoteIP:    relay.LANSubnetOf(view.Address),
	}
	if err := rule.Validate(); err != nil {
		a.firewallErr = err.Error()
		return
	}
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		a.firewallErr = err.Error()
		return
	}
	if err := journal.Add(a.dir, rule); err != nil {
		a.firewallErr = "防火墙恢复记录无法写入：" + err.Error()
		return
	}
	a.firewallBusy = true
	a.firewallErr = ""
	a.firewallNotice = "正在请求系统授权…"
	a.invalidate()
	update := func(fn func()) {
		if a.win != nil && !a.win.IsDestroyed() {
			a.win.Update(fn)
			return
		}
		fn()
	}
	go func() {
		err := relay.ApplyFirewallRule(rule)
		update(func() {
			a.firewallBusy = false
			if err != nil {
				a.firewallErr = err.Error() + "；规则可能未生效，恢复记录已保留"
				a.invalidate()
				return
			}
			if journalErr := journal.Confirm(a.dir); journalErr != nil {
				a.firewallErr = "规则已创建，但恢复记录未能确认：" + journalErr.Error()
				a.invalidate()
				return
			}
			a.firewallNotice = fmt.Sprintf("已放行端口 %d（仅本程序、专用网络、所选局域网范围）", rule.Port)
			a.invalidate()
		})
	}()
}

func (a *app) removeLanShareFirewall(port int) {
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		a.firewallErr = err.Error()
		return
	}
	var errs []string
	for _, rule := range journal.Rules {
		if port != 0 && rule.Port != port {
			continue
		}
		if err := relay.RemoveFirewallRule(rule.ID); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		_ = journal.Remove(a.dir, rule.ID)
	}
	if len(errs) > 0 {
		a.firewallErr = "部分规则未能移除：" + errs[0]
	} else {
		a.firewallNotice = "已移除本程序创建的放行规则"
	}
	a.invalidate()
}

// cleanupLanShareFirewall removes rules this app created that no longer match a
// running share. Callers pass 0 to remove all of them.
func (a *app) cleanupLanShareFirewall(keepPort int) {
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil || len(journal.Rules) == 0 {
		return
	}
	for _, rule := range journal.Rules {
		if keepPort != 0 && rule.Port == keepPort {
			continue
		}
		if err := relay.RemoveFirewallRule(rule.ID); err != nil {
			if a.bus != nil {
				a.bus.Add("app", "局域网分享：防火墙规则待清理："+err.Error())
			}
			continue
		}
		_ = journal.Remove(a.dir, rule.ID)
	}
}
