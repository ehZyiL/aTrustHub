package desktop

import (
	"fmt"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/components"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// lanShareStrip is the compact status line under the toolbar. It only appears
// while sharing is enabled, so it costs no room when the feature is unused.
func (a *app) lanShareStrip(c *ui.Context) {
	if a.lanShare == nil {
		return
	}
	view := a.lanShare.View()
	if !view.Enabled {
		return
	}
	t := c.Theme()
	color := t.TextMuted
	text := "局域网分享已开启"
	switch view.State {
	case relay.StateRunning:
		text = "局域网分享已开启"
		if view.Clients > 0 {
			text = fmt.Sprintf("局域网分享已开启 · 活跃客户端 %d", view.Clients)
		}
		color = t.Success
	case relay.StateWaiting:
		text = "局域网分享：等待接入点连接"
		color = t.Warning
	case relay.StateBlocked:
		text = "局域网分享：暂未运行，需处理"
		color = t.Danger
	case relay.StateStarting:
		text = "局域网分享：正在开启…"
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "●").FontSize(10).TextColor(color)
		ui.Text(c, text).FontSize(12).TextColor(color)
		ui.Row(c).Grow(1)
		if ui.Button(c, "管理").Label("管理局域网分享").FontSize(11).Clicked() {
			a.openLANShare()
		}
	})
}

// lanShareSection is the settings group. It is reachable in both simple and
// professional mode: sharing is not an advanced-only feature.
func (a *app) lanShareSection(c *ui.Context) {
	t := c.Theme()
	settingsGroup(c, "局域网分享", func() {
		if a.lanShare == nil {
			ui.Text(c, "局域网分享尚未初始化").FontSize(12).TextColor(t.TextMuted)
			return
		}
		view := a.lanShare.View()
		ui.Text(c, lanShareStateText(view)).FontSize(12).TextColor(lanShareStateColor(t, view)).Wrap()
		ui.Text(c, "把整个接入点的已授权资源分享给同一局域网的同事；未受管的公网目标使用同事自己的网络。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
		if view.Enabled {
			ui.Row(c).Gap(8).Children(func() {
				if ui.Button(c, "管理共享").FontSize(11).Clicked() {
					a.openLANShare()
				}
				if ui.Button(c, "关闭共享").FontSize(11).Clicked() {
					a.openLANShare()
					a.lanShareUI.confirmClose = view.Clients > 0
					if !a.lanShareUI.confirmClose {
						a.disableLANShare()
					}
				}
			})
			return
		}
		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "开启共享…").FontSize(11).Clicked() {
				a.openLANShare()
			}
			if ui.Button(c, "导入同事分享…").FontSize(11).Clicked() {
				a.openRelayImport()
			}
		})
	})
}

func lanShareStateText(view relay.View) string {
	if view.Paused {
		return "共享已暂停 · 设备授权已保留"
	}
	if view.FailureCode == "unavailable" {
		return "分享组件不可用：" + view.Failure
	}
	switch view.State {
	case relay.StateRunning:
		if view.Clients > 0 {
			return fmt.Sprintf("分享已开启 · 活跃客户端 %d（%s:%d）", view.Clients, view.Address, view.Port)
		}
		return fmt.Sprintf("分享已开启 · 等待同事连接（%s:%d）", view.Address, view.Port)
	case relay.StateStarting:
		return "正在开启共享…"
	case relay.StateWaiting:
		if view.Failure != "" {
			return "共享已启用，" + view.Failure
		}
		return "共享已启用，等待接入点连接"
	case relay.StateBlocked:
		if view.Failure != "" {
			return "共享已启用，暂未运行：" + view.Failure
		}
		return "共享已启用，暂未运行"
	case relay.StateStopping, relay.StateCleanupPending:
		return "正在停止共享…"
	default:
		return "未开启局域网分享"
	}
}

func lanShareStateColor(t *ui.Theme, view relay.View) ui.Color {
	switch view.State {
	case relay.StateRunning:
		return t.Success
	case relay.StateWaiting, relay.StateStarting, relay.StateStopping, relay.StateCleanupPending:
		return t.Warning
	case relay.StateBlocked:
		return t.Danger
	}
	return t.TextMuted
}

func (a *app) lanShareView(c *ui.Context) {
	d := &a.lanShareUI
	if !d.open {
		a.stopPairManage()
		return
	}
	a.drainLANShareResults()
	t := c.Theme()
	view := relay.View{}
	if a.lanShare != nil {
		view = a.lanShare.View()
	}
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "局域网分享", lanShareStateText(view))
			if a.lanShare == nil || a.lanShare.Component().Availability != components.Ready {
				ui.Text(c, "分享组件不可用，请检查安装包；基础 VPN 连接仍可使用。").Wrap()
				if ui.Button(c, "关闭面板").Clicked() {
					d.open = false
				}
				return
			}
			ui.Scroll(c).MaxHeight(a.dialogBodyMaxHeight()).MinHeight(0).
				ScrollbarInsets(4, 2, 4, 0).Children(func() {
				ui.Column(c).Padding(0, 14, 8, 0).Gap(10).Children(func() {
					ui.Text(c, "共享整个接入点，访问权限沿用该接入点；未受管公网使用同事自己的网络。").
						FontSize(12).TextColor(t.TextMuted).Wrap()
					ui.Text(c, "开启后记住状态，应用重启自动恢复；接入点未连接时等待。点击关闭共享后不再恢复。").
						FontSize(11).TextColor(t.TextMuted).Wrap()

					if !view.Enabled {
						a.lanShareEnableForm(c, d)
					} else {
						a.lanShareManageBody(c, d, view)
					}
					if d.notice != "" {
						ui.Text(c, d.notice).FontSize(11).TextColor(t.TextMuted).Wrap()
					}
					if d.err != "" {
						ui.Text(c, d.err).FontSize(11).TextColor(t.Danger).Wrap()
					}
					if d.confirmClose {
						ui.Text(c, fmt.Sprintf("将中断 %d 个活跃客户端的资源访问，当前口令立即失效，下次启动不再恢复。", view.Clients)).
							FontSize(12).TextColor(t.Danger).Wrap()
					}
				})
			})
			dialogFooter(c, func() {
				if ui.Button(c, "关闭面板").FontSize(11).Clicked() {
					d.open = false
				}
				ui.Row(c).Grow(1)
				if !view.Enabled {
					if d.busy {
						ui.Spinner(c)
					}
					if ui.PrimaryButton(c, "开启共享").FontSize(11).
						Disabled(d.busy || d.pointID == "").Clicked() {
						a.enableLANShare()
					}
					return
				}
				if ui.Button(c, "复制分享口令").FontSize(11).
					Disabled(view.State != relay.StateRunning).Clicked() {
					a.copyLANShareCode()
				}
				if ui.Button(c, "重试恢复").FontSize(11).Disabled(d.busy).Clicked() {
					a.retryLANShare()
				}
				if view.FailureCode == "persist" && !view.Enabled {
					if ui.Button(c, "重试保存关闭状态").FontSize(11).Disabled(d.busy).Clicked() {
						a.retryPersistLANShareDisable()
					}
				}
				if d.confirmClose {
					if ui.PrimaryButton(c, "确认关闭共享").FontSize(11).Background(t.Danger).
						TextColor(t.AccentText).Disabled(d.busy).Clicked() {
						a.disableLANShare()
					}
					return
				}
				if ui.Button(c, "关闭共享").FontSize(11).Disabled(d.busy).Clicked() {
					if view.Clients > 0 {
						d.confirmClose = true
						a.invalidate()
						return
					}
					a.disableLANShare()
				}
			})
		})
	})
	if !d.open {
		a.stopPairManage()
		// Closing the panel keeps a running share running; it never cancels a
		// saved enable intent. Only dropping an in-flight first enable was a
		// cancellation, and that path is not entered from here.
		d.confirmClose = false
		d.pairPIN = ""
	}
}

func (a *app) lanShareEnableForm(c *ui.Context, d *lanShareDraft) {
	points := a.shareablePoints()
	labels := make([]string, 0, len(points))
	byLabel := map[string]vpn.View{}
	selected := ""
	for _, v := range points {
		label := v.Name
		if v.State != vpn.StateOnline {
			label += "（未登录）"
		}
		labels = append(labels, label)
		byLabel[label] = v
		if v.ID == d.pointID {
			selected = label
		}
	}
	if selected == "" && len(labels) > 0 {
		selected = labels[0]
		d.pointID = byLabel[selected].ID
	}
	ui.Field(c, "共享接入点", func() {
		if len(labels) == 0 {
			ui.Text(c, "还没有可分享的 VPN 接入点").FontSize(12).TextColor(c.Theme().TextMuted)
			return
		}
		next := selected
		if ui.Select(c, &next, labels).Width(320).Changed() {
			if v, ok := byLabel[next]; ok {
				d.pointID = v.ID
				a.invalidate()
			}
		}
	})
	ifa := d.interfaceName
	iaLabels, iaByLabel := a.relayInterfaceChoices()
	if len(iaLabels) > 0 {
		current := ""
		for label, cand := range iaByLabel {
			if cand.IPv4 == d.ipv4 || (d.ipv4 == "" && cand.Name == ifa) {
				current = label
			}
		}
		if current == "" {
			// No remembered choice: start on the recommendation, if there is one.
			cands := newLANCandidates(lanAddresses{}.LANCandidates(), relayfirewall.SubnetOfAddress)
			if pick := recommendLAN(cands, outboundIPv4()); pick >= 0 {
				for label, cand := range iaByLabel {
					if cand.IPv4 == cands[pick].iface.IPv4 {
						current = label
					}
				}
			}
			if current == "" {
				current = iaLabels[0]
			}
			d.ipv4 = iaByLabel[current].IPv4
			d.interfaceName = iaByLabel[current].Name
		}
		ui.Field(c, "使用网络", func() {
			next := current
			if ui.Select(c, &next, iaLabels).Width(320).Changed() {
				cand := iaByLabel[next]
				d.ipv4, d.interfaceName = cand.IPv4, cand.Name
				a.invalidate()
			}
		})
	} else {
		ui.Text(c, "没有可用的局域网地址（需要已连接的 Wi-Fi 或有线网络）").
			FontSize(12).TextColor(c.Theme().Warning).Wrap()
	}
	ui.Column(c).Gap(4).Children(func() {
		ui.Checkbox(c, &d.discovery, "允许同一网络的同事发现")
		ui.Text(c, "同一网络的其他设备可以看到公开名称和连接地址；加入仍需邀请码配对或完整分享口令。").
			FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
		if d.discovery {
			ui.Field(c, "公开名称", func() {
				ui.TextInput(c, &d.discoveryName).
					Placeholder(a.discoveryNamePlaceholder()).
					Width(320).Changed()
				ui.Text(c, "留空使用默认名称；不会使用 VPN 名称、账号或计算机名。").
					FontSize(11).TextColor(c.Theme().TextMuted).Wrap()
			})
		}
	})
	ui.Checkbox(c, &d.advanced, "高级选项（固定端口）")
	if d.advanced {
		ui.Field(c, "监听端口", func() {
			ui.TextInput(c, &d.portText).Placeholder("留空自动分配").Width(140)
		})
	}
}

func (a *app) lanShareManageBody(c *ui.Context, d *lanShareDraft, view relay.View) {
	t := c.Theme()
	subnet := ""
	if view.Address != "" {
		if got, err := relayfirewall.SubnetOfAddress(view.Address); err == nil {
			subnet = got
		}
	}
	rows := [][2]string{
		{"共享接入点", orDash(view.PointName)},
		{"监听地址", orDash(view.Address)},
		{"所在网段", orDash(subnet)},
		{"端口", fmt.Sprint(orZero(view.Port))},
		{"运行状态", stateLabelOf(view.State)},
		{"重启后恢复", "是（点击关闭共享后不再恢复）"},
	}
	if !view.CertExpiry.IsZero() {
		rows = append(rows, [2]string{"证书有效期至", view.CertExpiry.Format("2006-01-02")})
	}
	if subnet != "" {
		ui.Text(c, "同事需要和本机在同一网段（"+subnet+"）内，并且没有被 Wi-Fi 访客网络或 AP 隔离挡住。").
			FontSize(11).TextColor(t.TextMuted).Wrap()
	}
	for _, row := range rows {
		ui.Row(c).Gap(8).Children(func() {
			ui.Text(c, row[0]).FontSize(12).TextColor(t.TextMuted).Width(110)
			ui.Text(c, row[1]).FontSize(12).Wrap()
		})
	}
	if d.showCode {
		if code, err := a.lanShareCode(); err == nil {
			ui.Text(c, "分享口令（含访问权限，请通过可信渠道发送）：").FontSize(11).TextColor(t.TextMuted)
			ui.Text(c, code).Font("monospace").FontSize(10).Wrap()
		} else {
			ui.Text(c, "共享尚未运行，暂时没有可用的分享口令").FontSize(11).TextColor(t.TextMuted)
		}
	}
	ui.Row(c).Gap(8).Children(func() {
		if ui.Button(c, "显示分享口令").FontSize(11).Disabled(view.State != relay.StateRunning).Clicked() {
			d.showCode = !d.showCode
		}
		if ui.Button(c, "更换口令").Label("更换口令并断开现有连接").FontSize(11).Disabled(true).Clicked() {
		}
	})
	if view.State == relay.StateBlocked && view.Failure != "" {
		ui.Text(c, "原因："+view.Failure).FontSize(12).TextColor(t.Danger).Wrap()
	}
	a.lanShareDiscoveryView(c, view)
	if view.Pairing {
		a.pairingManageView(c, view)
	}
	if view.State == relay.StateRunning {
		info := relayfirewall.FirewallInfo()
		ui.Column(c).Gap(3).Children(func() {
			for _, line := range info.Lines {
				ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
			}
			if info.Automatic {
				ui.Text(c, "本程序只在点击「允许局域网连接」并完成系统授权后修改防火墙，不会在开启共享时静默改规则。").
					FontSize(11).TextColor(t.TextMuted).Wrap()
			}
		})
		a.lanShareFirewallView(c, view)
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c, "连接诊断").Label("分享状态检查").FontSize(11).Clicked() {
				a.openLANShareDiagnose()
			}
		})
	}
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "—"
	}
	return v
}

func orZero(v int) int {
	if v <= 0 {
		return 0
	}
	return v
}

func stateLabelOf(s relay.State) string {
	switch s {
	case relay.StateRunning:
		return "分享已开启"
	case relay.StateStarting:
		return "正在开启"
	case relay.StateWaiting:
		return "等待接入点连接"
	case relay.StateBlocked:
		return "需要处理"
	case relay.StateStopping:
		return "正在停止"
	case relay.StateCleanupPending:
		return "关闭中，等待清理"
	default:
		return "未开启"
	}
}

func boolLabel(v bool) string {
	if v {
		return "是"
	}
	return "否"
}
