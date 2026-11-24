package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/relay"
)

// This file owns every firewall rule the app creates. Rules outlive the process,
// so the same coordinator is used for the explicit button, 关闭共享, quitting,
// losing the share source, deleting a node and crash recovery. Creating one is
// always an explicit user action: nothing here prompts for elevation by itself.

// firewallRules is the process-wide coordinator. It is created on first use so a
// test app without a data directory never touches the disk.
func (a *app) firewallRules() *relay.Rules {
	a.fwOnce.Do(func() {
		a.fwRules = relay.NewRules(a.dir, relay.NewElevatedFirewall(), func(format string, args ...any) {
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf(format, args...))
			}
		})
	})
	return a.fwRules
}

// fwSeenState remembers the share state whose rules were already reconciled, so
// the per-frame check does no disk work unless something actually changed.
type fwSeenState struct {
	init    bool
	state   relay.State
	port    int
	address string
}

// syncLanShareFirewallIfNeeded reconciles on state changes only. It never asks
// for elevation, so it is safe to call from the render path.
func (a *app) syncLanShareFirewallIfNeeded() {
	if a.dir == "" {
		return
	}
	view := a.lanShareViewState()
	if a.fwSeen.init && a.fwSeen.state == view.State && a.fwSeen.port == view.Port && a.fwSeen.address == view.Address {
		return
	}
	a.fwSeen.init = true
	a.fwSeen.state, a.fwSeen.port, a.fwSeen.address = view.State, view.Port, view.Address
	a.reconcileLanShareFirewall(view)
}

// syncLanShareFirewall reconciles immediately, without waiting for a frame. It is
// called after an action that changes the share state.
func (a *app) syncLanShareFirewall() {
	if a.dir == "" {
		return
	}
	view := a.lanShareViewState()
	a.fwSeen.init = true
	a.fwSeen.state, a.fwSeen.port, a.fwSeen.address = view.State, view.Port, view.Address
	a.reconcileLanShareFirewall(view)
}

// lanShareViewState is the share state for firewall purposes. No controller means
// no share, which still has to clean up whatever a previous run left behind.
func (a *app) lanShareViewState() relay.View {
	if a.lanShare == nil {
		return relay.View{}
	}
	return a.lanShare.View()
}

// reconcileLanShareFirewall schedules the reconciliation off the UI thread.
//
// Cleanup can need elevation (deleting a rule is a privileged operation), so it
// must never run inside a render pass or a click handler. Only one reconciliation
// runs at a time; a request arriving while one is running is folded into the next
// pass instead of queueing up.
func (a *app) reconcileLanShareFirewall(view relay.View) {
	if !a.fwRunning.CompareAndSwap(false, true) {
		a.fwAgain.Store(true)
		return
	}
	go func() {
		for {
			a.doReconcileLanShareFirewall(view)
			if !a.fwAgain.Swap(false) {
				break
			}
			view = a.lanShareViewState()
		}
		a.fwRunning.Store(false)
	}()
}

// doReconcileLanShareFirewall is the synchronous core: it keeps exactly the rules
// a running share justifies. On a running share the recorded rules are verified
// first (so a rule removed outside the app is forgotten instead of being reported
// as in place); every other recorded rule is deleted, because the share it
// belonged to is no longer running in that shape.
func (a *app) doReconcileLanShareFirewall(view relay.View) {
	rules := a.firewallRules()
	desired, err := a.desiredFirewallRules(view)
	if err != nil {
		a.setFirewallError(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), relay.FirewallOpBudget)
	defer cancel()
	var errs []error
	if view.State == relay.StateRunning && len(desired) > 0 {
		if _, verifyErrs := rules.Recover(ctx, desired); len(verifyErrs) > 0 {
			errs = append(errs, verifyErrs...)
		}
	}
	if _, reconcileErrs := rules.Reconcile(ctx, desired); len(reconcileErrs) > 0 {
		errs = append(errs, reconcileErrs...)
	}
	if len(errs) > 0 {
		// A failed cleanup stays in the journal and is retried on the next start;
		// the share itself must not be blocked by it.
		a.setFirewallError("防火墙规则待清理：" + errs[0].Error())
		if a.bus != nil {
			a.bus.Add("app", "局域网分享：防火墙规则待清理："+errs[0].Error())
		}
	}
}

// firewallPost runs fn on the UI thread. Before the first window exists there is
// no UI thread to defer to, so the work runs inline; once the window has been
// destroyed the journal is the record and UI fields are left alone.
func (a *app) firewallPost(fn func()) {
	if a.win == nil {
		fn()
		return
	}
	if a.win.IsDestroyed() {
		return
	}
	a.win.Update(fn)
}

// setFirewallError records a failure that must be visible in the panel.
func (a *app) setFirewallError(msg string) {
	a.firewallPost(func() {
		a.firewallErr = msg
		a.invalidate()
	})
}

// desiredFirewallRules returns the recorded rules that still describe the running
// share exactly. A rule whose port, subnet or program no longer matches is not
// desired: the authorization it carried does not cover the new shape.
func (a *app) desiredFirewallRules(view relay.View) ([]relay.FirewallRule, error) {
	if view.State != relay.StateRunning || view.Port == 0 {
		return nil, nil
	}
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		return nil, err
	}
	exe, exeErr := os.Executable()
	subnet, subnetErr := relay.SubnetOfAddress(view.Address)
	var desired []relay.FirewallRule
	for _, entry := range journal.Entries {
		rule := entry.Rule
		if rule.Port != view.Port {
			continue
		}
		if exeErr == nil && rule.ProgramPath != exe {
			continue
		}
		if subnetErr == nil && subnet != "" && rule.RemoteIP != subnet {
			continue
		}
		desired = append(desired, rule)
	}
	return desired, nil
}

// lanShareFirewallView renders the platform guidance and, where this build can
// act, the two explicit actions.
func (a *app) lanShareFirewallView(c *ui.Context, view relay.View) {
	if view.State != relay.StateRunning {
		return
	}
	info := relay.FirewallInfo()
	t := c.Theme()
	for _, line := range info.Lines {
		ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
	}
	if !info.Automatic {
		return
	}
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		ui.Text(c, "防火墙恢复记录无法读取："+err.Error()).FontSize(11).TextColor(t.Danger).Wrap()
		return
	}
	var own []relay.FirewallJournalEntry
	for _, entry := range journal.Entries {
		if entry.Rule.Port == view.Port {
			own = append(own, entry)
		}
	}
	for _, entry := range own {
		switch entry.State {
		case relay.FirewallEntryConfirmed:
			ui.Text(c, fmt.Sprintf("已记录本程序端口 %d 的放行规则。", entry.Rule.Port)).FontSize(11).TextColor(t.TextMuted).Wrap()
		case relay.FirewallEntryPending:
			ui.Text(c, "上次授权未确认，规则状态未知；启动或关闭共享时会先核对再处理。").FontSize(11).TextColor(t.Warning).Wrap()
		default:
			ui.Text(c, "上次清理未完成，记录已保留，下次启动会重试。").FontSize(11).TextColor(t.Warning).Wrap()
		}
	}
	ui.Row(c).Gap(8).Children(func() {
		label := "允许局域网连接"
		if len(own) > 0 {
			label = "重新确认放行规则"
		}
		if ui.Button(c, label).FontSize(11).Disabled(a.firewallBusy).Clicked() {
			a.allowLanShareFirewall(view)
		}
		if len(own) > 0 && ui.Button(c, "移除放行规则").FontSize(11).Disabled(a.firewallBusy).Clicked() {
			a.removeLanShareFirewall()
		}
	})
	if a.firewallNotice != "" {
		ui.Text(c, a.firewallNotice).FontSize(11).TextColor(t.TextMuted).Wrap()
	}
	if a.firewallErr != "" {
		ui.Text(c, a.firewallErr).FontSize(11).TextColor(t.Danger).Wrap()
	}
}

// allowLanShareFirewall builds the minimal rule and hands it to the elevated
// helper. The rule needs a verified subnet: guessing /24 could either let in a
// neighbouring network or lock out colleagues on a /16 office LAN.
func (a *app) allowLanShareFirewall(view relay.View) {
	if a.firewallBusy {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		a.firewallErr = "无法确定程序路径：" + err.Error()
		a.invalidate()
		return
	}
	subnet, err := relay.SubnetOfAddress(view.Address)
	if err != nil {
		a.firewallErr = "无法确定该地址所在网卡的子网掩码，未创建规则：" + err.Error()
		a.invalidate()
		return
	}
	rule := relay.FirewallRule{
		ID:          relay.NewFirewallRuleID(view.Port, time.Now()),
		Name:        "Connect Hub 局域网分享",
		ProgramPath: exe,
		Port:        view.Port,
		Profile:     "private",
		RemoteIP:    subnet,
		CreatedAt:   time.Now().Unix(),
	}
	if err := rule.Validate(); err != nil {
		a.firewallErr = err.Error()
		a.invalidate()
		return
	}
	a.firewallBusy = true
	a.firewallErr = ""
	a.firewallNotice = "正在请求系统授权…"
	a.invalidate()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), relay.FirewallOpBudget)
		defer cancel()
		result, applyErr := a.firewallRules().Apply(ctx, rule)
		if applyErr == nil && result.Outcome == relay.FirewallFailed {
			applyErr = errors.New(result.Detail)
		}
		a.firewallPost(func() {
			a.firewallBusy = false
			switch {
			case result.Outcome == relay.FirewallCreated:
				a.firewallNotice = fmt.Sprintf("已放行端口 %d（仅本程序、专用网络、%s）", rule.Port, rule.RemoteIP)
				a.firewallErr = ""
			case result.Outcome == relay.FirewallCanceled:
				// The user declined, or sharing was closed meanwhile. Nothing was
				// changed; do not claim the port is open.
				a.firewallNotice = "已取消系统授权，未修改防火墙规则"
			case result.Outcome == relay.FirewallDenied:
				a.firewallErr = "系统拒绝授权，未修改防火墙规则"
			case result.Outcome == relay.FirewallTimeout:
				a.firewallErr = "等待系统授权超时，规则状态未知；已保留待核对记录"
			case applyErr != nil:
				a.firewallErr = applyErr.Error() + "；恢复记录已保留"
			default:
				a.firewallErr = result.Detail
			}
			a.invalidate()
		})
	}()
}

// removeLanShareFirewall removes every rule this app recorded. It is the same
// path 关闭共享 uses, so there is one answer to "what happens to the rule".
func (a *app) removeLanShareFirewall() {
	if a.firewallBusy {
		return
	}
	a.firewallBusy = true
	a.firewallErr = ""
	a.invalidate()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), relay.FirewallOpBudget)
		defer cancel()
		_, errs := a.firewallRules().Reconcile(ctx, nil)
		a.firewallPost(func() {
			a.firewallBusy = false
			if len(errs) > 0 {
				a.firewallErr = "部分规则未能移除：" + errs[0].Error()
			} else {
				a.firewallNotice = "已移除本程序创建的放行规则"
			}
			a.invalidate()
		})
	}()
}

// cancelPendingFirewallOps tells the coordinator that in-flight creations are no
// longer wanted, so a prompt answered after 关闭共享 cannot leave a rule behind.
func (a *app) cancelPendingFirewallOps() {
	if a.fwRules == nil {
		return
	}
	for _, entry := range a.fwRules.Pending() {
		a.fwRules.Cancel(entry.OperationID)
	}
}
