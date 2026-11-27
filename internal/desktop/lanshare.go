package desktop

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// lanShareResult is one finished async action. Results travel through a channel
// instead of being written from a worker goroutine, so the UI thread stays the
// only writer of the draft.
type lanShareResult struct {
	action string
	err    error
	notice string
	// saveFailed marks a switch-off whose preference could not be written; the
	// panel then offers a retry instead of silently claiming success.
	saveFailed bool
}

// lanShareDraft is the 局域网分享 panel state. Only the explicit create response
// supplies a temporary PIN; long-lived share credentials stay in the controller.
type lanShareDraft struct {
	pair           relay.PairView
	pairPIN        string
	pairBusy       bool
	pairAt         time.Time
	pairResults    chan pairManageResult
	pairCancel     context.CancelFunc
	pairConfirmAll bool
	open           bool
	// pointID is the single shared access point. There is no resource list.
	pointID       string
	interfaceName string
	ipv4          string
	portText      string
	advanced      bool
	busy          bool
	busyAction    string
	err           string
	notice        string
	confirmClose  bool
	showCode      bool
	// discovery is the 允许同事发现 checkbox of the enable form. It is an
	// explicit choice saved with the rest of the intent, default-checked only
	// when the user has never chosen before.
	discovery        bool
	discoveryName    string
	discoveryTouched bool
	// discoveryEditing opens the inline rename field of the running panel.
	discoveryEditing bool
	discoveryBusy    bool
	// discoverySavePending means the user turned discovery off but the
	// preference could not be written; the network is already stopped and the
	// panel offers a retry.
	discoverySavePending bool
	results              chan lanShareResult
}

// lanShareChanged is the controller's change notification. Discovery follows the
// share from here, not from the render loop.
func (a *app) lanShareChanged() {
	a.kickLANDiscovery()
	a.invalidateCoalesced()
}

// resumeLANShare runs after the configuration and credentials are loaded. A
// share that was switched off stays off; one that was on waits for its access
// point instead of logging in anything by itself.
func (a *app) resumeLANShare() {
	if a.lanShare == nil {
		return
	}
	if err := a.lanShare.Restore(context.Background()); err != nil {
		a.tunLogf("局域网分享恢复：%v", err)
	}
	// Verify any rule left from the previous run before this run relies on it:
	// an unverified rule is either reused (same share, same scope) or removed.
	a.syncLanShareFirewall()
	a.resumeLANDiscovery()
}

// shutdownLANShare stops serving but keeps the enable intent, so the next start
// resumes it.
func (a *app) shutdownLANShare() {
	// The announcement goes before the listener: colleagues must not be able to
	// dial a share that is already going away.
	a.shutdownLANDiscovery()
	if a.lanShare != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = a.lanShare.Shutdown(ctx)
		cancel()
	}
	// The listener is closed, so the rule no longer serves anything. A failure
	// keeps the journal entry for the next start; it must not block quitting —
	// but it does get a bounded chance to finish before the process exits.
	a.cancelPendingFirewallOps()
	a.reconcileLanShareFirewall(a.lanShareViewState())
	if !a.awaitFirewallIdle(relayfirewall.FirewallShutdownBudget) {
		a.tunLogf("局域网分享：防火墙规则清理未在退出前完成，已保留待处理记录")
	}
}

// lanShareEnabled reports whether the share intent is on.
func (a *app) lanShareEnabled() bool {
	return a.lanShare != nil && a.lanShare.View().Enabled
}

// openLANShare prepares the panel from the real controller state. Opening it
// never starts a listener.
func (a *app) openLANShare() {
	a.stopPairManage()
	d := &a.lanShareUI
	d.open = true
	d.pairPIN = ""
	d.pairAt = time.Time{}
	d.err, d.notice = "", ""
	d.confirmClose = false
	d.showCode = false
	d.advanced = false
	d.portText = ""
	d.busy = false
	if d.results == nil {
		d.results = make(chan lanShareResult, 4)
	}
	if a.lanShare == nil {
		d.err = "局域网分享尚未初始化"
		return
	}
	settings := a.lanShare.Settings()
	d.pointID = settings.PointID
	d.interfaceName = settings.InterfaceName
	d.ipv4 = settings.PreferredIPv4
	// A share that was never asked about discovery shows the box checked in the
	// enable form (an explicit choice is required to save), while a share that
	// already chose false keeps it unchecked.
	d.discovery = true
	d.discoveryTouched = false
	if settings.DiscoveryEnabled != nil {
		d.discovery = *settings.DiscoveryEnabled
		d.discoveryTouched = true
	}
	d.discoveryName = settings.DiscoveryName
	if settings.Port != 0 {
		d.portText = fmt.Sprint(settings.Port)
	}
	if d.pointID == "" {
		// Default to the access point currently in use, but never select a
		// relay node: sharing a relay would loop. When nothing is online yet
		// the first shareable point is preselected, because choosing an
		// offline point legitimately means "enabled, waiting".
		for _, p := range a.cfg.Points {
			if p.Protocol == model.ProtocolLANRelay {
				continue
			}
			if v, ok := a.mgr.View(p.ID); ok && v.State == vpn.StateOnline {
				d.pointID = p.ID
				break
			}
		}
		if d.pointID == "" {
			for _, p := range a.cfg.Points {
				if p.Protocol == model.ProtocolLANRelay {
					continue
				}
				d.pointID = p.ID
				break
			}
		}
	}
	a.invalidate()
}

// openLANShareFor opens the panel with one access point preselected, which is
// what the per-point detail action does.
func (a *app) openLANShareFor(pointID string) {
	a.openLANShare()
	d := &a.lanShareUI
	if pointID != "" {
		d.pointID = pointID
		// The panel re-reads the usable addresses for this run; a stale
		// interface choice from another network is not reused silently.
		d.interfaceName, d.ipv4 = "", ""
	}
	a.invalidate()
}

// shareablePoints lists the access points a share may bind.
func (a *app) shareablePoints() []vpn.View {
	var out []vpn.View
	for _, p := range a.cfg.Points {
		if p.Protocol == model.ProtocolLANRelay {
			continue
		}
		if v, ok := a.mgr.View(p.ID); ok {
			out = append(out, v)
		}
	}
	return out
}

func (a *app) pointLabel(id string) string {
	if p := a.cfg.Find(id); p != nil {
		return p.Name
	}
	return ""
}

func (a *app) lanShareCode() (string, error) {
	if a.lanShare == nil {
		return "", fmt.Errorf("局域网分享尚未初始化")
	}
	return a.lanShare.ShareCode()
}

// drainLANShareResults applies finished async actions on the UI thread.
func (a *app) drainLANShareResults() {
	a.drainPairManageResults()
	d := &a.lanShareUI
	for {
		select {
		case res := <-d.results:
			if res.action == "pause" {
				d.pairAt = time.Time{}
			}
			d.busy = false
			d.busyAction = ""
			if res.action == "discovery" || res.action == "discovery-name" ||
				res.action == "discovery-retry" {
				d.discoveryBusy = false
				if res.err == nil {
					d.discoveryEditing = false
					d.discoverySavePending = false
				}
				if res.saveFailed {
					d.discoverySavePending = true
				}
			}
			if res.err != nil {
				d.err = res.err.Error()
			} else if res.notice != "" {
				d.notice = res.notice
			}
			if res.action == "disable" && res.err == nil {
				d.open = false
			}
		default:
			return
		}
	}
}

func (a *app) postLANShareResult(res lanShareResult) {
	d := &a.lanShareUI
	if d.results == nil {
		d.results = make(chan lanShareResult, 4)
	}
	select {
	case d.results <- res:
	default:
	}
	a.invalidate()
}

func (a *app) enableLANShare() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		d.err = "局域网分享尚未初始化"
		return
	}
	if d.pointID == "" {
		d.err = "请选择要共享的接入点"
		return
	}
	port := 0
	if d.advanced {
		text := strings.TrimSpace(d.portText)
		if text != "" {
			n, err := parsePort(text, "监听端口")
			if err != nil {
				d.err = err.Error()
				return
			}
			port = n
		}
	}
	if name := strings.TrimSpace(d.discoveryName); d.discovery && name != "" {
		if err := model.ValidDiscoveryName(name); err != nil {
			d.err = err.Error()
			return
		}
	}
	opts := relay.EnableOptions{
		PointID:       d.pointID,
		InterfaceName: d.interfaceName,
		PreferredIPv4: d.ipv4,
		Port:          port,
		Discovery:     d.discovery,
		DiscoveryName: d.discoveryName,
	}
	d.busy, d.busyAction = true, "enable"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.Enable(context.Background(), opts)
		notice := "共享已开启。复制分享口令发给同事；应用重启后会自动恢复。"
		a.postLANShareResult(lanShareResult{action: "enable", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) disableLANShare() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		return
	}
	a.stopPairManage()
	d.busy, d.busyAction = true, "disable"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.Disable(context.Background())
		notice := ""
		if err == nil {
			notice = "共享已关闭，下次启动不再恢复。"
			// The rule only exists for the share port; it goes with the share. A
			// creation still waiting on the elevation prompt is revoked too.
			a.cancelPendingFirewallOps()
			a.syncLanShareFirewall()
		}
		a.postLANShareResult(lanShareResult{action: "disable", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) retryLANShare() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		return
	}
	d.busy, d.busyAction = true, "retry"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.Retry(context.Background())
		a.postLANShareResult(lanShareResult{action: "retry", err: err})
	}()
	a.invalidate()
}

// retryPersistLANShareDisable re-attempts saving Enabled=false after a failed
// disable, and only then removes the recovery identity.
func (a *app) retryPersistLANShareDisable() {
	d := &a.lanShareUI
	if a.lanShare == nil {
		return
	}
	d.busy, d.busyAction = true, "retry-persist"
	d.err, d.notice = "", ""
	go func() {
		err := a.lanShare.RetryPersistDisable()
		notice := ""
		if err == nil {
			notice = "关闭状态已保存，下次启动不会恢复。"
		}
		a.postLANShareResult(lanShareResult{action: "retry-persist", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) copyLANShareCode() {
	code, err := a.lanShareCode()
	if err != nil {
		a.lanShareUI.err = err.Error()
		a.invalidate()
		return
	}
	a.copyText(code)
	a.lanShareUI.notice = "分享口令已复制"
	a.invalidate()
}
