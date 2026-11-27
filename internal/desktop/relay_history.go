package desktop

import (
	"errors"
	"fmt"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// saveRelaySnapshot is the relay connector's persistence hook. It runs before a
// snapshot may be announced as usable, so a crash right after going online still
// leaves the attribution behind: without it a known managed target could fall
// back to the original network on the next start.
func (a *app) saveRelaySnapshot(pointID string, ident vpn.RelaySnapshotSource, resources *workeripc.ResourceSnapshot) error {
	if resources == nil {
		return nil
	}
	source := store.RelaySource{
		ShareID:     ident.ShareID,
		Fingerprint: ident.Fingerprint,
		Label:       ident.Fingerprint + "/" + ident.ShareID,
	}
	write, err := a.store.SaveRelayKnown(pointID, source, resources)
	if err != nil {
		if errors.Is(err, store.ErrRelayKnownStaleSource) {
			// The node was deleted or re-imported while this session was running.
			// Its snapshot can never be trusted for the current configuration, and
			// turning on protection would refuse ordinary public traffic for a node
			// the user can no longer see. Drop the callback instead.
			if a.bus != nil {
				a.bus.Add("app", "配置：已忽略已删除或已更换身份的分享的历史归属回调")
			}
			return err
		}
		// The protection gap must stay visible: the gate refuses unknown targets
		// instead of pretending the history is intact.
		if a.mgr != nil {
			a.mgr.BlockRelayAutoConnect(pointID, true)
		}
		return err
	}
	if write.Incomplete {
		// The cache this snapshot merged into was corrupt or missing, so targets
		// owned by the lost history are unknowable. Protect what is known and
		// keep the node blocked until the user decides otherwise.
		a.mgr.SeedRelayKnownIncomplete(pointID, resources)
	} else {
		a.mgr.SeedRelayKnown(pointID, resources)
	}
	// The marker check reads the store, not a.cfg: this goroutine must not touch
	// the UI-thread copy of the configuration.
	initialized := false
	persisted := a.store.Config()
	if p := persisted.Find(pointID); p != nil && p.Relay != nil {
		initialized = p.Relay.HistoryInitialized
	}
	if !initialized {
		if err := a.store.SetRelayHistoryInitialized(pointID); err != nil {
			// The protective cache exists, so the marker can be retried later;
			// the snapshot must not be published as authorized until both steps
			// succeeded.
			return err
		}
		// The marker is visible in the panel, so the UI copy of the config has
		// to catch up. It is re-read on the UI thread; this goroutine never
		// writes a.cfg (see requestConfigReload).
		a.requestConfigReload()
	}
	return nil
}

// loadRelayKnown seeds every imported node's attribution before anything
// connects, and turns on the protection gate when a cache cannot be trusted.
func (a *app) loadRelayKnown() {
	if a.mgr == nil {
		return
	}
	for _, p := range a.cfg.Points {
		if p.Protocol != model.ProtocolLANRelay {
			continue
		}
		initialized := p.Relay != nil && p.Relay.HistoryInitialized
		known, err := a.store.LoadRelayKnown(p.ID)
		switch {
		case err != nil:
			a.mgr.BlockRelayAutoConnect(p.ID, true)
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属无法读取，已暂停自动连接（可手动登录修复）：%v", p.Name, err))
			}
		case known == nil:
			if initialized {
				// A node that had a cache and lost it cannot prove which
				// targets are managed.
				a.mgr.BlockRelayAutoConnect(p.ID, true)
				if a.bus != nil {
					a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属缺失，已暂停自动连接并暂缓未知目标直连", p.Name))
				}
			}
		case known.Incomplete:
			// The file exists but is known to be missing entries: the node stays
			// out of automatic login and the gate stays on.
			a.mgr.SeedRelayKnownIncomplete(p.ID, known.Resources)
			if a.bus != nil {
				a.bus.Add("app", fmt.Sprintf("配置：局域网分享「%s」的历史归属不完整，已暂停自动连接；旧目标仍不会直连", p.Name))
			}
		default:
			a.mgr.SeedRelayKnown(p.ID, known.Resources)
		}
	}
}

// clearRelayHistoryProtection is the explicit user decision to accept that the
// lost history cannot be recovered: their old owned targets will no longer be
// recognised as managed. Nothing calls this automatically.
// relayHistoryConfirmView asks before dropping the protection for a node: the
// consequence is that targets from the lost history stop being recognised.
func (a *app) relayHistoryConfirmView(c *ui.Context) {
	if a.askingClearRelayHistory == "" {
		return
	}
	id := a.askingClearRelayHistory
	p := a.cfg.Find(id)
	if p == nil {
		a.askingClearRelayHistory = ""
		return
	}
	t := c.Theme()
	open := true
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "解除历史保护", p.Name)
			ui.Text(c, "该分享的历史归属缓存已损坏或缺失，无法证明哪些地址以前属于这个接入点。").
				FontSize(12).Wrap()
			ui.Text(c, "解除后，这些地址将不再被视为受管目标，可能按普通公网从本机直连。").
				FontSize(12).TextColor(t.Warning).Wrap()
			dialogFooter(c, func() {
				if ui.Button(c, "保持保护").FontSize(11).Clicked() {
					a.askingClearRelayHistory = ""
					a.invalidate()
				}
				ui.Row(c).Grow(1)
				if ui.PrimaryButton(c, "确认解除").FontSize(11).Clicked() {
					a.askingClearRelayHistory = ""
					if err := a.clearRelayHistoryProtection(id); err != nil {
						a.toast = "解除失败：" + err.Error()
					}
					a.invalidate()
				}
			})
		})
	})
	if !open {
		a.askingClearRelayHistory = ""
		a.invalidate()
	}
}

func (a *app) clearRelayHistoryProtection(pointID string) error {
	if a.store != nil {
		if err := a.store.ClearRelayKnownIncomplete(pointID); err != nil {
			return err
		}
	}
	if a.mgr != nil {
		a.mgr.BlockRelayAutoConnect(pointID, false)
	}
	a.toast = "已解除该分享的历史保护：之前归属不明目标今后按普通规则处理"
	a.invalidate()
	return nil
}
