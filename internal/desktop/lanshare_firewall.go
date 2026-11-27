package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
)

// This file owns every firewall rule the app creates. Rules outlive the process,
// so the same coordinator is used for the explicit button, 关闭共享, quitting,
// losing the share source, deleting a node and crash recovery. Creating one is
// always an explicit user action: nothing here prompts for elevation by itself.

// firewallRules is the process-wide coordinator. It is created on first use so a
// test app without a data directory never touches the disk.
func (a *app) firewallRules() *relayfirewall.Rules {
	a.fwOnce.Do(func() {
		exec := a.fwExec
		if exec == nil {
			exec = relayfirewall.NewElevatedFirewall()
		}
		a.fwRules = relayfirewall.NewRules(a.dir, exec, func(format string, args ...any) {
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf(format, args...))
			}
		})
	})
	return a.fwRules
}

// fwSeenState remembers the share state whose rules were already reconciled, so
// the per-frame check does no disk work unless something actually changed.
//
// It is written from the render path and from background action goroutines
// (启用/关闭共享), so it carries its own lock instead of relying on the UI
// thread: sharing state is read by both sides.
type fwSeenState struct {
	mu      sync.Mutex
	init    bool
	state   relay.State
	port    int
	address string
}

// changed records view and reports whether it differs from the last reconciled
// state. One call both compares and updates, so two callers cannot interleave a
// stale read with a fresh write.
func (s *fwSeenState) changed(view relay.View) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.init && s.state == view.State && s.port == view.Port && s.address == view.Address {
		return false
	}
	s.init = true
	s.state, s.port, s.address = view.State, view.Port, view.Address
	return true
}

// syncLanShareFirewallIfNeeded reconciles on state changes only. It never asks
// for elevation, so it is safe to call from the render path.
func (a *app) syncLanShareFirewallIfNeeded() {
	if a.dir == "" {
		return
	}
	view := a.lanShareViewState()
	if !a.fwSeen.changed(view) {
		return
	}
	a.reconcileLanShareFirewall(view)
}

// syncLanShareFirewall reconciles immediately, without waiting for a frame. It is
// called after an action that changes the share state.
func (a *app) syncLanShareFirewall() {
	if a.dir == "" {
		return
	}
	view := a.lanShareViewState()
	a.fwSeen.changed(view)
	a.reconcileLanShareFirewall(view)
}

// awaitFirewallIdle waits for the scheduled reconciliation to finish, up to
// budget. It exists for shutdown: leaving right after starting the goroutine
// would let the process exit before the rule was removed.
func (a *app) awaitFirewallIdle(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for !a.fwQueue.idle() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

// lanShareViewState is the share state for firewall purposes. No controller means
// no share, which still has to clean up whatever a previous run left behind.
func (a *app) lanShareViewState() relay.View {
	if a.lanShare == nil {
		return relay.View{}
	}
	return a.lanShare.View()
}

// firewallQueue serialises reconciliations without a lost-wakeup window.
//
// The whole handover runs under one mutex: a request either sees a running worker
// and marks it for one more pass, or it starts a new worker. There is no moment
// where the worker has decided to stop but still looks busy to a new request.
type firewallQueue struct {
	mu      sync.Mutex
	running bool
	pending bool
}

// start reports whether the caller must launch the worker.
func (q *firewallQueue) start() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.running {
		q.pending = true
		return false
	}
	q.running = true
	return true
}

// more reports whether another pass is needed. A false result means the queue is
// idle, so the next start() launches a new worker.
func (q *firewallQueue) more() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending {
		q.pending = false
		return true
	}
	q.running = false
	return false
}

// idle reports whether no worker is running.
func (q *firewallQueue) idle() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.running
}

// reconcileLanShareFirewall schedules the reconciliation off the UI thread.
//
// Cleanup can need elevation (deleting a rule is a privileged operation), so it
// must never run inside a render pass or a click handler. Only one reconciliation
// runs at a time; a request arriving while one is running is folded into the next
// pass instead of queueing up. The worker always reads the current share state,
// so a folded request can never be served with a stale view.
func (a *app) reconcileLanShareFirewall(relay.View) {
	if !a.fwQueue.start() {
		return
	}
	go func() {
		for {
			a.doReconcileLanShareFirewall(a.lanShareViewState())
			if !a.fwQueue.more() {
				return
			}
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), relayfirewall.FirewallOpBudget)
	defer cancel()
	var errs []error
	if len(desired) > 0 {
		// Verify before reusing: a rule removed outside the app must be forgotten
		// instead of being reported as in place.
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

// desiredFirewallRules returns the recorded rules that still describe this share
// exactly. A rule whose port, subnet or program no longer matches is not desired:
// the authorization it carried does not cover the new shape.
//
// A share that is starting or waiting for its VPN keeps its rule: it is on its way
// back to serving the same instance, and deleting the rule would make the user
// approve a new elevation prompt on every restart.
func (a *app) desiredFirewallRules(view relay.View) ([]relayfirewall.FirewallRule, error) {
	port, address := view.Port, view.Address
	switch view.State {
	case relay.StateRunning:
	case relay.StateStarting, relay.StateWaiting:
		if a.lanShare != nil {
			settings := a.lanShare.Settings()
			if port == 0 {
				port = settings.Port
			}
			if address == "" {
				address = settings.PreferredIPv4
			}
		}
	default:
		return nil, nil
	}
	if port == 0 {
		return nil, nil
	}
	journal, err := relayfirewall.LoadFirewallJournal(a.dir)
	if err != nil {
		return nil, err
	}
	exe, exeErr := os.Executable()
	subnet, subnetErr := relayfirewall.SubnetOfAddress(address)
	var desired []relayfirewall.FirewallRule
	for _, entry := range journal.Entries {
		rule := entry.Rule
		if rule.Port != port {
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
	info := relayfirewall.FirewallInfo()
	t := c.Theme()
	for _, line := range info.Lines {
		ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
	}
	if !info.Automatic {
		return
	}
	journal, err := relayfirewall.LoadFirewallJournal(a.dir)
	if err != nil {
		ui.Text(c, "防火墙恢复记录无法读取："+err.Error()).FontSize(11).TextColor(t.Danger).Wrap()
		return
	}
	var own []relayfirewall.FirewallJournalEntry
	for _, entry := range journal.Entries {
		if entry.Rule.Port == view.Port {
			own = append(own, entry)
		}
	}
	for _, entry := range own {
		switch entry.State {
		case relayfirewall.FirewallEntryConfirmed:
			ui.Text(c, fmt.Sprintf("已记录本程序端口 %d 的放行规则。", entry.Rule.Port)).FontSize(11).TextColor(t.TextMuted).Wrap()
		case relayfirewall.FirewallEntryPending:
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
	subnet, err := relayfirewall.SubnetOfAddress(view.Address)
	if err != nil {
		a.firewallErr = "无法确定该地址所在网卡的子网掩码，未创建规则：" + err.Error()
		a.invalidate()
		return
	}
	rule := relayfirewall.FirewallRule{
		ID:          relayfirewall.NewFirewallRuleID(view.Port, time.Now()),
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
		ctx, cancel := context.WithTimeout(context.Background(), relayfirewall.FirewallOpBudget)
		defer cancel()
		result, applyErr := a.firewallRules().Apply(ctx, rule)
		if applyErr == nil && result.Outcome == relayfirewall.FirewallFailed {
			applyErr = errors.New(result.Detail)
		}
		a.firewallPost(func() {
			a.firewallBusy = false
			switch {
			case result.Outcome == relayfirewall.FirewallCreated:
				a.firewallNotice = fmt.Sprintf("已放行端口 %d（仅本程序、专用网络、%s）", rule.Port, rule.RemoteIP)
				a.firewallErr = ""
			case result.Outcome == relayfirewall.FirewallCanceled:
				// The user declined, or sharing was closed meanwhile. Nothing was
				// changed; do not claim the port is open.
				a.firewallNotice = "已取消系统授权，未修改防火墙规则"
			case result.Outcome == relayfirewall.FirewallDenied:
				a.firewallErr = "系统拒绝授权，未修改防火墙规则"
			case result.Outcome == relayfirewall.FirewallTimeout:
				a.firewallErr = "等待系统授权超时，规则状态未知；已保留待核对记录"
			case applyErr != nil:
				a.firewallErr = applyErr.Error() + "；恢复记录已保留"
			default:
				a.firewallErr = result.Detail
			}
			a.invalidate()
		})
		// A prompt answered after the share stopped running must not leave a
		// rule behind: reconcile against the state as it is now.
		a.syncLanShareFirewall()
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
		ctx, cancel := context.WithTimeout(context.Background(), relayfirewall.FirewallOpBudget)
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
	if a.dir == "" {
		return
	}
	// Go through firewallRules() so the lazy construction is published by the
	// same sync.Once for every caller, never by a bare field read.
	rules := a.firewallRules()
	for _, entry := range rules.Pending() {
		rules.Cancel(entry.OperationID)
	}
}
