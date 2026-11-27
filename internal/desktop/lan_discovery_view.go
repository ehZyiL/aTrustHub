package desktop

import (
	"sort"
	"strconv"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
)

// lanShareDiscoveryView is the discovery block of the 局域网分享 panel. It only
// edits the preference: switching it never restarts the share, revokes the
// token or touches the access point.
func (a *app) lanShareDiscoveryView(c *ui.Context, view relay.View) {
	t := c.Theme()
	d := &a.lanShareUI
	status := a.discoveryStatus()
	name := view.DiscoveryName
	if strings.TrimSpace(name) == "" {
		shareID := ""
		if a.lanShare != nil {
			shareID = a.lanShare.Settings().ShareID
		}
		name = model.DefaultDiscoveryName(shareID)
	}

	label, color := discoveryStatusText(t, view, status)
	ui.Column(c).Gap(5).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "局域网发现").FontSize(12).TextColor(t.TextMuted).Width(110)
			ui.Text(c, label).FontSize(12).TextColor(color).Wrap()
			ui.Row(c).Grow(1)
			button := "允许被发现"
			if view.DiscoveryEnabled {
				button = "停止被发现"
			}
			if ui.Button(c, button).FontSize(11).Disabled(d.discoveryBusy || !view.Enabled).Clicked() {
				a.toggleLANDiscovery(!view.DiscoveryEnabled)
			}
		})
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "公开名称").FontSize(12).TextColor(t.TextMuted).Width(110)
			if d.discoveryEditing {
				ui.TextInput(c, &d.discoveryName).Width(240)
				if ui.Button(c, "保存名称").FontSize(11).Disabled(d.discoveryBusy).Clicked() {
					a.saveLANDiscoveryName(d.discoveryName)
				}
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					d.discoveryEditing = false
					d.discoveryName = view.DiscoveryName
				}
			} else {
				ui.Text(c, name).FontSize(12).Wrap()
				ui.Row(c).Grow(1)
				if ui.Button(c, "改名").FontSize(11).Disabled(d.discoveryBusy || !view.Enabled).Clicked() {
					d.discoveryEditing = true
					d.discoveryName = view.DiscoveryName
				}
			}
		})
		ui.Text(c, "同一网络的其他设备可以看到该名称和连接地址；新设备可用限时邀请码申请，旧版本仍需完整分享口令。发现本身不授予信任。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
		ui.Text(c, "同事收不到时：确认双方在同一网段，且系统防火墙允许本程序接收 5353/UDP 组播"+
			"（Windows：专用网络并开启「网络发现」）。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
		if d.discoverySavePending {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "发现已停止，但偏好没有保存成功：重启后可能恢复。").
					FontSize(11).TextColor(t.Warning).Wrap()
				ui.Row(c).Grow(1)
				if ui.Button(c, "重试保存").FontSize(11).Disabled(d.discoveryBusy).Clicked() {
					a.retryLANDiscoverySave()
				}
			})
		}
		if status.State == discovery.StatusFailed {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "发现不可用："+status.Message+"（分享仍在运行，可以使用口令）").
					FontSize(11).TextColor(t.Warning).Wrap()
				ui.Row(c).Grow(1)
				if ui.Button(c, "重试发现").FontSize(11).Clicked() {
					a.kickLANDiscovery()
				}
			})
		}
	})
}

// discoveryStatusText maps the publisher state to the panel's wording. "已发布"
// never claims that a colleague received or reached the share.
func discoveryStatusText(t *ui.Theme, view relay.View, status discovery.Status) (string, ui.Color) {
	switch status.State {
	case discovery.StatusPublished:
		return "正在发布（已注册，不代表同事已收到）", t.Success
	case discovery.StatusPending:
		return "正在发布…", t.TextMuted
	case discovery.StatusFailed:
		return "发现不可用", t.Warning
	}
	if view.DiscoveryEnabled {
		if view.State == relay.StateRunning {
			return "等待发布", t.TextMuted
		}
		return "等待共享可用", t.Warning
	}
	return "未允许发现", t.TextMuted
}

func (a *app) toggleLANDiscovery(on bool) {
	d := &a.lanShareUI
	name := d.discoveryName
	d.discoveryBusy = true
	d.err, d.notice = "", ""
	post := a.lanShareResultPoster()
	go func() {
		err := a.setLANDiscoveryPreference(on, name)
		notice := ""
		if err == nil && on {
			notice = "已允许同一网络的同事发现这条分享。"
		}
		if err == nil && !on {
			notice = "已停止被发现；分享和口令继续有效。"
		}
		post(lanShareResult{
			action: "discovery", err: err, notice: notice,
			saveFailed: err != nil && !on,
		})
	}()
	a.invalidate()
}

// retryLANDiscoverySave re-attempts the failed switch-off write.
func (a *app) retryLANDiscoverySave() {
	d := &a.lanShareUI
	d.discoveryBusy = true
	post := a.lanShareResultPoster()
	go func() {
		err := a.retryLANDiscoveryPreference()
		notice := ""
		if err == nil {
			notice = "发现偏好已保存。"
		}
		post(lanShareResult{action: "discovery-retry", err: err, notice: notice})
	}()
	a.invalidate()
}

func (a *app) saveLANDiscoveryName(name string) {
	d := &a.lanShareUI
	d.discoveryBusy = true
	d.err, d.notice = "", ""
	post := a.lanShareResultPoster()
	go func() {
		err := a.setLANDiscoveryPreference(true, name)
		post(lanShareResult{action: "discovery-name", err: err, notice: "公开名称已更新"})
	}()
	a.invalidate()
}

// relayDiscoveryBody is the 发现局域网分享 list. It shows only what was learned
// from the network: a name, an address and a port. Joining still needs a code.
func (a *app) relayDiscoveryBody(c *ui.Context, d *relayImportDraft) {
	t := c.Theme()
	disc := a.lanDisc
	if disc == nil {
		ui.Text(c, "发现未启用，请粘贴分享口令加入。").FontSize(12).TextColor(t.TextMuted).Wrap()
		return
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "使用网络").FontSize(12).TextColor(t.TextMuted)
		labels, byLabel := a.discoveryInterfaceChoices()
		current := "自动选择"
		for label, name := range byLabel {
			if name == disc.ui.ifaceName {
				current = label
			}
		}
		next := current
		all := append([]string{"自动选择"}, labels...)
		if ui.Select(c, &next, all).Width(220).Changed() {
			a.setLANDiscoveryInterface(byLabel[next])
		}
		ui.Row(c).Grow(1)
		if ui.Button(c, "刷新").FontSize(11).Disabled(disc.ui.starting).Clicked() {
			a.refreshLANDiscovery()
		}
	})
	ui.Text(c, "只浏览当前网卡；发现不会发起连接，也不会读取已保存的凭据。").
		FontSize(11).TextColor(t.TextMuted).Wrap()

	if disc.ui.err != "" {
		ui.Column(c).Gap(3).Children(func() {
			ui.Text(c, disc.ui.err).FontSize(11).TextColor(t.Warning).Wrap()
			ui.Text(c, "仍然可以粘贴分享口令加入。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
		})
	}
	if len(disc.ui.cands) == 0 {
		// The first seconds must not claim "nothing there": multicast answers
		// take a moment, and a premature empty state reads as "it is broken".
		if disc.ui.searching {
			ui.Text(c, "正在查找局域网分享…").FontSize(12).TextColor(t.TextMuted)
		} else {
			ui.Text(c, "暂未发现分享。请确认主机已开启共享并允许被发现；也可以粘贴分享口令。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
			// Discovery is bidirectional: the query goes out and the answer has
			// to come back in, so an inbound block looks exactly like an empty
			// network. Naming the check is the only way the user can tell them
			// apart without a packet capture.
			ui.Text(c, "若一直为空：确认双方在同一网段，且系统防火墙允许本程序接收 5353/UDP 组播"+
				"（Windows：专用网络并开启「网络发现」）。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
		}
		return
	}
	for _, cand := range disc.ui.cands {
		cand := cand
		ui.Column(c).Key("disc:"+cand.Key()).Padding(8, 10).Gap(3).Radius(8).
			Border(1, t.Border).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				name := cand.Name
				if name == "" {
					name = "未命名分享"
				}
				ui.Text(c, name).FontSize(13).Bold().Wrap()
				ui.Row(c).Grow(1)
				a.relayDiscoveryAction(c, d, cand)
			})
			ui.Text(c, cand.Address+":"+strconv.Itoa(cand.Port)+" · "+cand.Interface).
				FontSize(11).TextColor(t.TextMuted)
			if !cand.Compatible() {
				ui.Text(c, "分享协议暂不兼容，请核对双方版本。").FontSize(11).TextColor(t.Warning)
			}
		})
	}
}

// relayDiscoveryAction renders 加入 / 已导入 / 地址不同 for one candidate.
func (a *app) relayDiscoveryAction(c *ui.Context, d *relayImportDraft, cand discovery.Candidate) {
	t := c.Theme()
	if existing, sameEndpoint := a.findRelayPointByShareID(cand); existing != nil {
		if sameEndpoint {
			ui.Text(c, "已导入，待验证").FontSize(11).TextColor(t.TextMuted)
			if ui.Button(c, "连接").FontSize(11).Clicked() {
				a.closeRelayImport()
				go a.mgr.Connect(existing.ID)
				a.toast = "正在连接「" + existing.Name + "」"
			}
			if cand.Pairing && existing.Relay.PairingUnconfirmed {
				if ui.Button(c, "重新配对").FontSize(11).Clicked() {
					a.stopPairImport()
					d.pinned = cand
					d.pinnedKey = cand.Key()
					d.tab = 2
					d.deviceName = "我的设备"
					d.pairProgress = relay.PairProgress{}
					d.pairStoredID = ""
					d.err = ""
					a.closeLANDiscovery()
					a.invalidate()
				}
			}
			return
		}
		ui.Text(c, "地址不同，需新口令核对").FontSize(11).TextColor(t.Warning)
		return
	}
	if ui.Button(c, "加入").FontSize(11).Disabled(!cand.Compatible()).Clicked() {
		d.pinned = cand
		d.pinnedKey = cand.Key()
		d.tab = 1
		if cand.Pairing {
			d.tab = 2
			d.deviceName = "我的设备"
		}
		d.err = ""
		a.closeLANDiscovery()
		a.invalidate()
	}
}

// discoveryInterfaceChoices lists every browsing network the machine has. The
// picker must show all of them even though only a bounded set browses at once,
// otherwise an adapter beyond the bound could not be chosen at all.
func (a *app) discoveryInterfaceChoices() ([]string, map[string]string) {
	var labels []string
	byLabel := map[string]string{}
	seen := map[string]bool{}
	for _, cand := range a.allLANInterfaces() {
		if seen[cand.Name] {
			continue
		}
		seen[cand.Name] = true
		label := cand.Name
		labels = append(labels, label)
		byLabel[label] = cand.Name
	}
	sort.Strings(labels)
	return labels, byLabel
}

// findRelayPointByShareID matches an already imported node by share ID and
// reports whether its saved endpoint equals the discovered one. A match is a
// convenience, never proof of identity: the saved fingerprint and credentials
// still decide the connection.
func (a *app) findRelayPointByShareID(cand discovery.Candidate) (*model.AccessPoint, bool) {
	for i := range a.cfg.Points {
		p := &a.cfg.Points[i]
		if p.Protocol != model.ProtocolLANRelay || p.Relay == nil || p.Relay.ShareID != cand.ShareID {
			continue
		}
		// Only an identical endpoint may reuse the saved node. A different
		// address is a different offer that needs a fresh code.
		return p, p.Server == cand.Address && p.Port == cand.Port
	}
	return nil, false
}

// discoveryNamePlaceholder is the example shown in the name field. It must be
// stable across frames: a random example would flicker on every render.
func (a *app) discoveryNamePlaceholder() string {
	shareID := ""
	if a.lanShare != nil {
		shareID = a.lanShare.Settings().ShareID
	}
	if shareID == "" {
		return "例如：会议室共享"
	}
	return model.DefaultDiscoveryName(shareID)
}
