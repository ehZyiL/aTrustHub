package desktop

import (
	"context"
	"fmt"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
)

type pairManageResult struct {
	view relay.PairView
	err  error
}

// Each request owns its mailbox. An explicit action can replace a passive
// refresh without letting that refresh's late snapshot overwrite the action.
func (a *app) stopPairManage() {
	d := &a.lanShareUI
	d.pairResults = nil
	if d.pairCancel != nil {
		d.pairCancel()
		d.pairCancel = nil
	}
	d.pairBusy = false
}

func (a *app) pairManageAction(operation, id string) {
	d := &a.lanShareUI
	if d.pairBusy || d.busy || a.lanShare == nil {
		return
	}
	if operation == "list" && d.pairResults != nil {
		return
	}
	a.stopPairManage()
	d.pairBusy = operation != "list"
	d.pairAt = time.Now()
	if operation != "list" {
		d.err = ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	d.pairCancel = cancel
	results := make(chan pairManageResult, 1)
	d.pairResults = results
	control := a.lanShare
	go func() {
		defer cancel()
		v, err := control.PairControl(ctx, relay.PairCommand{Operation: operation, ID: id})
		results <- pairManageResult{view: v, err: err}
		if operation == "list" {
			a.invalidateCoalesced()
		} else {
			a.invalidate()
		}
	}()
}

func (a *app) drainPairManageResults() {
	d := &a.lanShareUI
	select {
	case res := <-d.pairResults:
		a.stopPairManage()
		if res.err != nil {
			d.err = res.err.Error()
			return
		}
		v := res.view
		if v.PIN != "" {
			d.pairPIN = v.PIN
		}
		if v.Invitation == nil || v.Invitation.Cancelled || (d.pair.Invitation != nil && d.pair.Invitation.ID != v.Invitation.ID && v.PIN == "") {
			d.pairPIN = ""
		}
		d.pair = v
		d.pair.PIN = ""
	default:
	}
}

func (a *app) pairingManageView(c *ui.Context, view relay.View) {
	d := &a.lanShareUI
	t := c.Theme()
	if view.Paused {
		d.pairPIN = ""
		d.pair.Invitation = nil
		d.pair.Requests = nil
	}
	if a.windowVisible() {
		if !d.busy && !d.pairBusy && d.pairResults == nil && time.Since(d.pairAt) >= time.Second {
			a.pairManageAction("list", "")
		}
		// Keep the next frame armed even when an action reset pairAt or a slow
		// refresh is still running. Hidden or closed panels stop scheduling.
		c.After(time.Second)
	}
	busy := d.busy || d.pairBusy
	inv := d.pair.Invitation
	activeInvite := inv != nil && !inv.Cancelled && time.Now().Before(inv.ExpiresAt) && inv.Approved < inv.Capacity
	ui.Column(c).Gap(6).Children(func() {
		ui.Text(c, "邀请码与设备授权").FontSize(13).Bold()
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, "生成邀请码").Disabled(busy || view.State != relay.StateRunning).Clicked() {
				a.pairManageAction("create", "")
			}
			if ui.Button(c, "取消邀请码").Disabled(busy || !activeInvite).Clicked() {
				a.pairManageAction("cancel", "")
			}
			label := "暂停共享"
			if view.Paused {
				label = "恢复共享"
			}
			if ui.Button(c, label).Disabled(busy).Clicked() {
				a.stopPairManage()
				d.busy, d.busyAction = true, "pause"
				d.err, d.notice = "", ""
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				d.pauseCancel = cancel
				post := a.lanShareResultPoster()
				control := a.lanShare
				paused := view.Paused
				go func() {
					defer cancel()
					var err error
					if paused {
						err = control.ResumeSharing(ctx)
					} else {
						err = control.PauseSharing(ctx)
					}
					post(lanShareResult{action: "pause", err: err})
				}()
			}
		})
		if inv := d.pair.Invitation; inv != nil {
			remaining := max(0, int(time.Until(inv.ExpiresAt).Seconds()))
			status := fmt.Sprintf("剩余 %d 秒 · 剩余名额 %d/%d", remaining, max(0, inv.Capacity-inv.Approved), inv.Capacity)
			if inv.Cancelled {
				status = "邀请码已取消"
			} else if remaining == 0 {
				status = "邀请码已过期"
			} else if inv.Approved >= inv.Capacity {
				status = "邀请码名额已用完"
			}
			ui.Text(c, status).FontSize(12).Wrap()
			if d.pairPIN != "" && !inv.Cancelled && remaining > 0 && inv.Approved < inv.Capacity {
				ui.Text(c, d.pairPIN).Font("monospace").FontSize(22).Bold()
			}
		}
		ui.Text(c, "请双方核对会话校验码和设备标识后逐台批准。名称由申请者提供；取消/过期只阻止新申请。待批准请求独立保留 5 分钟。").FontSize(11).TextColor(t.TextMuted).Wrap()
		ui.Text(c, fmt.Sprintf("待批准与最近请求（最多 %d 条）", relay.MaxPairRequests)).FontSize(12).Bold()
		for _, r := range d.pair.Requests {
			r := r
			ui.Column(c).Key("pair:" + r.ID).Gap(3).Children(func() {
				ui.Text(c, r.Name+" · "+pairStateText(r.State)+" · 来源 "+r.Source).FontSize(12).Wrap()
				ui.Text(c, "校验码 "+r.Verification+" · 设备 "+r.DeviceID).Font("monospace").FontSize(10).Wrap()
				if r.State == "pending" {
					ui.Row(c).Gap(8).Children(func() {
						if ui.Button(c, "批准").Label("批准 " + r.ID).Disabled(busy).Clicked() {
							a.pairManageAction("approve", r.ID)
						}
						if ui.Button(c, "拒绝").Label("拒绝 " + r.ID).Disabled(busy).Clicked() {
							a.pairManageAction("reject", r.ID)
						}
					})
				}
			})
		}
		ui.Text(c, fmt.Sprintf("已配对设备（%d）", len(d.pair.Devices))).FontSize(12).Bold()
		for _, device := range d.pair.Devices {
			device := device
			ui.Column(c).Key("device:" + device.ID).Gap(3).Children(func() {
				ui.Text(c, device.Name+" · "+device.ID).FontSize(11).Wrap()
				if ui.Button(c, "撤销此设备").Label("撤销 " + device.ID).Disabled(busy).Clicked() {
					a.pairManageAction("revoke", device.ID)
				}
			})
		}
		if d.pairConfirmAll {
			ui.Text(c, "将断开并撤销全部 v2 设备；旧 v1 完整口令仍有效。要让所有口令失效请使用关闭共享。").FontSize(11).TextColor(t.Warning).Wrap()
			if ui.Button(c, "确认撤销全部设备").Disabled(busy).Clicked() {
				d.pairConfirmAll = false
				a.pairManageAction("revoke-all", "")
			}
			if ui.Button(c, "取消撤销").Clicked() {
				d.pairConfirmAll = false
			}
		} else if ui.Button(c, "撤销全部已配对设备…").Disabled(busy || len(d.pair.Devices) == 0).Clicked() {
			d.pairConfirmAll = true
		}
		ui.Text(c, "暂停共享保留已配对设备授权，但当前邀请码和临时配对请求会失效；恢复共享后已配对设备免输邀请码，新设备需重新生成邀请码。旧 v1 完整口令属于共享授权，无法单独识别或撤销其中一台设备；关闭共享会销毁主机身份并使全部口令和授权失效。").FontSize(11).TextColor(t.TextMuted).Wrap()
	})
}

func pairStateText(state string) string {
	switch state {
	case "pending":
		return "等待主机批准"
	case "approved":
		return "已批准，待领取"
	case "claimed":
		return "已确认领取"
	case "rejected":
		return "已拒绝"
	case "expired":
		return "请求已超时"
	case "revoked":
		return "授权已撤销"
	case "exhausted":
		return "邀请码名额已用完"
	case "saving":
		return "正在安全保存设备凭据"
	}
	return state
}

type pairStartResult struct {
	attempt relay.PairAttempt
	err     error
}

func (a *app) stopPairImport() {
	d := &a.relayImport
	// Detach result mailboxes before cancelling. Ack/start may already have
	// succeeded; only this UI thread owns which attempt may update the dialog.
	d.pairAck = nil
	d.pairStarts = nil
	d.pairStoredID = ""
	d.pairProgress = relay.PairProgress{}
	if d.pairCancel != nil {
		d.pairCancel()
		d.pairCancel = nil
	}
	if d.pairAttempt != nil {
		attempt := d.pairAttempt
		go attempt.Close()
		d.pairAttempt = nil
	}
	d.pin = ""
	d.busy = false
}

func (a *app) beginPairImport() {
	d := &a.relayImport
	if a.pairStart == nil {
		d.err = "配对组件不可用"
		return
	}
	pin := d.pin
	a.stopPairImport()
	d.err = ""
	d.busy = true
	// Every attempt generates a new private key. A retry must replace the
	// previous unconfirmed checkpoint rather than acknowledge the old one.
	d.pairStoredID = ""
	d.pairProgress = relay.PairProgress{}
	d.pairAck = nil
	d.pairStarts = make(chan pairStartResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	d.pairCancel = cancel
	results := d.pairStarts
	target := relay.PairTarget{Host: d.pinned.Address, Port: d.pinned.Port, ShareID: d.pinned.ShareID, Name: d.deviceName, HostName: d.pinned.Name}
	d.pin = ""
	start := a.pairStart
	go func() {
		attempt, err := start(ctx, target, pin)
		if ctx.Err() != nil {
			if attempt != nil {
				attempt.Close()
			}
			return
		}
		results <- pairStartResult{attempt, err}
		// Cancellation can race with publishing into the buffered mailbox.
		// The attempt remains context-owned even if its UI never drains it.
		if attempt != nil {
			context.AfterFunc(ctx, func() { _ = attempt.Close() })
		}
		a.invalidateCoalesced()
	}()
}

func (a *app) drainPairImport() {
	d := &a.relayImport
	select {
	case err := <-d.pairAck:
		d.pairAck = nil
		if err != nil {
			d.err = err.Error() + "；设备已安全保存，可关闭此面板并连接"
			d.busy = false
		} else {
			a.finishPairImport()
			return
		}
	default:
	}
	select {
	case result := <-d.pairStarts:
		d.pairStarts = nil
		d.busy = false
		if result.err != nil {
			d.err = result.err.Error()
		} else {
			d.pairAttempt = result.attempt
		}
	default:
	}
	if d.pairAttempt != nil {
		for {
			select {
			case progress, ok := <-d.pairAttempt.Updates():
				if !ok {
					if d.pairProgress.Request.State == "pending" {
						d.err = "pair_channel_lost: 配对通道已结束，请重新申请"
					}
					attempt := d.pairAttempt
					d.pairAttempt = nil
					go attempt.Close()
					return
				}
				d.pairProgress = progress
				if progress.Request.State == "saving" && progress.Code != nil {
					if err := a.persistPairImport(*progress.Code); err != nil {
						d.err = err.Error()
						a.stopPairImport()
						return
					}
					if err := d.pairAttempt.Stored(context.Background()); err != nil {
						d.err = err.Error()
						a.stopPairImport()
						return
					}
				}
				if progress.Error != "" {
					d.err = progress.Error
				}
			default:
				return
			}
		}
	}
}

func (a *app) pairImportView(c *ui.Context, d *relayImportDraft) {
	t := c.Theme()
	ui.Text(c, "邀请码配对："+d.pinned.Name).FontSize(13).Bold()
	ui.Text(c, fmt.Sprintf("%s:%d", d.pinned.Address, d.pinned.Port)).FontSize(11)
	if d.pairAttempt == nil && d.pairProgress.Request.ID == "" {
		ui.Field(c, "8 位邀请码", func() { ui.TextInput(c, &d.pin).Placeholder("主机上显示的限时数字码") })
		ui.Field(c, "设备显示名称", func() { ui.TextInput(c, &d.deviceName) })
		if ui.PrimaryButton(c, "安全申请配对").Disabled(d.busy || len(d.pin) != relay.InviteDigits).Clicked() {
			a.beginPairImport()
		}
	} else {
		r := d.pairProgress.Request
		ui.Text(c, pairStateText(r.State)).FontSize(12).Bold()
		ui.Text(c, "会话校验码："+r.Verification).Font("monospace").FontSize(18).Wrap()
		ui.Text(c, "设备标识："+r.DeviceID).Font("monospace").FontSize(10).Wrap()
		ui.Text(c, "请与主机上的校验码和设备标识逐项核对；主机批准后再确认领取。发现名称不能证明主机身份。").FontSize(11).TextColor(t.TextMuted).Wrap()
		if d.pairStoredID != "" {
			ui.Text(c, "设备密钥和主机身份已安全保存。响应丢失时，可在节点列表中连接；拒绝或超时后可在发现列表重新配对。").FontSize(11).TextColor(t.TextMuted).Wrap()
		}
		if r.State == "approved" && d.pairProgress.Code != nil {
			if ui.PrimaryButton(c, "确认领取并连接").Disabled(d.busy || d.pairAttempt == nil).Clicked() {
				a.claimPairImport()
			}
		}
		if d.pairAttempt == nil && !d.busy {
			if ui.Button(c, "重新申请").Clicked() {
				d.pairProgress = relay.PairProgress{}
				d.pairStoredID = ""
				d.err = ""
			}
		}
	}
	if d.busy {
		ui.Spinner(c)
	}
	// Updates are channel-owned and drained by the UI thread. Only an open
	// active pairing schedules another frame; closed dialogs leave no ticker.
	if d.busy || d.pairAttempt != nil {
		time.AfterFunc(250*time.Millisecond, a.invalidateCoalesced)
	}
}

// Persist both the authenticated host pin and the independent private seed
// before acknowledging receipt. A lost ack leaves a reusable local device.
func (a *app) claimPairImport() {
	d := &a.relayImport
	if d.pairProgress.Code == nil || d.pairAttempt == nil {
		return
	}
	code := *d.pairProgress.Code
	if err := a.persistPairImport(code); err != nil {
		d.err = err.Error()
		return
	}
	d.busy = true
	d.pairAck = make(chan error, 1)
	ack := d.pairAck
	attempt := d.pairAttempt
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ack <- attempt.Ack(ctx)
		a.invalidateCoalesced()
	}()
}

func (a *app) persistPairImport(code relay.ShareCode) error {
	d := &a.relayImport
	if d.pairStoredID == "" {
		existing := a.findRelayPoint(code)
		if existing != nil && !existing.Relay.PairingUnconfirmed {
			return fmt.Errorf("此主机已导入，请使用现有节点连接")
		}
		id := model.NewID()
		oldSecret := ""
		if existing != nil {
			id = existing.ID
			var err error
			oldSecret, err = a.store.Password(id)
			if err != nil {
				return err
			}
		}
		point := model.AccessPoint{ID: id, Name: code.Name, Protocol: model.ProtocolLANRelay, Server: code.Host, Port: code.Port, InPool: true, Relay: &model.RelayPointOptions{Version: 2, ShareID: code.ShareID, CertificateSHA256: code.Fingerprint, PairingUnconfirmed: true}}
		if existing != nil {
			point = *existing
			opts := *existing.Relay
			opts.PairingUnconfirmed = true
			point.Relay = &opts
			point.Server, point.Port = code.Host, code.Port
		}
		if point.Name == "" {
			point.Name = "已配对分享 " + code.Host
		}
		point.Normalize()
		if err := point.Validate(); err != nil {
			return err
		}
		if err := a.store.SetPassword(point.ID, code.Token); err != nil {
			return fmt.Errorf("设备凭据无法安全保存：%w", err)
		}
		before := a.store.Config()
		if _, err := a.store.Update(func(cfg *model.Config) error {
			if current := cfg.Find(id); current != nil {
				*current = point
			} else {
				cfg.Add(point)
			}
			return nil
		}); err != nil {
			_ = a.store.SetPassword(point.ID, oldSecret)
			return err
		}
		if err := a.store.Save(); err != nil {
			_, _ = a.store.Update(func(cfg *model.Config) error { *cfg = before; return nil })
			_ = a.store.SetPassword(point.ID, oldSecret)
			return fmt.Errorf("配置保存失败：%w", err)
		}
		d.pairStoredID = point.ID
		cfg := a.store.Config()
		a.setConfig(cfg)
		a.mgr.Apply(cfg)
	}
	return nil
}

func (a *app) finishPairImport() {
	id := a.relayImport.pairStoredID
	if id == "" {
		return
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		if p := cfg.Find(id); p != nil && p.Relay != nil {
			p.Relay.PairingUnconfirmed = false
		}
		return nil
	}); err != nil {
		a.relayImport.err = err.Error()
		a.relayImport.busy = false
		return
	}
	if err := a.store.Save(); err != nil {
		a.relayImport.err = "领取成功，确认状态保存失败；设备凭据已保存，可在节点列表连接"
		a.relayImport.busy = false
		return
	}
	cfg := a.store.Config()
	a.setConfig(cfg)
	a.mgr.Apply(cfg)
	a.closeRelayImport()
	a.toast = "设备授权已保存，正在连接共享主机"
	go a.mgr.Connect(id)
}
