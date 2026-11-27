package desktop

import (
	"fmt"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"net"
	"strconv"
	"strings"
	"time"
)

// statusBanner reports connection state independently of DNS and TCP reachability.
func (a *app) statusBanner(c *ui.Context, views []vpn.View) {
	t := c.Theme()
	online, connecting, attention := 0, 0, 0
	for _, v := range views {
		switch v.State {
		case vpn.StateConnecting:
			connecting++
		case vpn.StateOnline:
			online++
			if pointNeedsAttention(v) {
				attention++
			}
		case vpn.StateError:
			attention++
		}
	}

	tone := t.TextMuted
	switch {
	case attention > 0 || connecting > 0:
		tone = t.Warning
	case online > 0:
		tone = t.Success
	}
	ui.Row(c).AlignItems(ui.Center).Gap(8).Padding(6, 10).Radius(8).
		Background(t.Surface).Border(1, t.Border).Children(func() {
		ui.Row(c).Size(7, 7).Radius(3.5).Background(tone)
		ui.Text(c, fmt.Sprintf("%d 个接入点在线", online)).FontSize(13).Bold()
		if connecting > 0 {
			ui.Text(c, fmt.Sprintf("%d 个正在连接", connecting)).FontSize(12).TextColor(t.TextMuted)
		}
		if attention > 0 {
			ui.Text(c, fmt.Sprintf("%d 个需要处理", attention)).FontSize(12).TextColor(t.Warning)
		}
		ui.Row(c).Grow(1)
		if a.sysProxyOn.Load() {
			ui.Text(c, "分流策略").FontSize(12).TextColor(t.TextMuted)
			mode := a.cfg.Settings.Routing.Label()
			sel := ui.Select(c, &mode, routingLabelStrings()).Width(104)
			if sel.Changed() {
				a.setRouting(routingFromLabel(mode))
			}
		}
	})
}

// recentFailures 把最近几条失败放到首屏卡片下面：首屏下半屏不再空着，
// 需要处理的事一看就能去日志里查。
//
// 日志入口按模式走：简单模式没有「访问日志」页，落到设置页的日志分区，
// 否则会跳到一个导航里不存在的页面。
func (a *app) recentFailures(c *ui.Context) {
	if a.simpleMode() {
		a.recentFailuresFor(c, func() { a.openSettingsAt(settingLogs) })
		return
	}
	a.recentFailuresFor(c, func() { a.tab = 2 })
}

// recentFailuresFor 是同一块面板的可换动作版本。
func (a *app) recentFailuresFor(c *ui.Context, onOpen func()) {
	t := c.Theme()
	var fails []vpn.LogEntry
	for _, e := range a.bus.Tail(200) {
		if e.Source == vpn.AccessFail {
			fails = append(fails, e)
		}
	}
	if len(fails) == 0 {
		return
	}
	if len(fails) > 4 {
		fails = fails[len(fails)-4:]
	}
	panel := ui.Column(c).Radius(12).Border(1, t.Border).Background(t.Surface)
	panel.Children(func() {
		ui.Row(c).Padding(10, 12).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "最近的失败").FontSize(13).Bold()
			ui.Text(c, fmt.Sprintf("最近 %d 条", len(fails))).FontSize(11).TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			if ui.Button(c, "查看访问日志").FontSize(11).Clicked() {
				onOpen()
			}
		})
		ui.Divider(c)
		for _, e := range fails {
			ui.Row(c).Padding(6, 12).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Row(c).Size(5, 5).Radius(2.5).Background(t.Danger)
				ui.Text(c, e.At.Format("15:04:05")).Font("monospace").
					FontSize(11).TextColor(t.TextMuted)
				ui.Text(c, e.Line).FontSize(11).Grow(1).MinWidth(0).Ellipsis("…")
			})
		}
	})
}

func (a *app) emptyState(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Padding(32).Gap(10).Center().Radius(12).
		Border(1, t.Border).Background(t.Surface).Children(func() {
		ui.Text(c, "还没有接入点").FontSize(15).Bold()
		ui.Text(c, "添加 EasyConnect / aTrust 服务器地址、用户名和密码，连接后启动代理浏览器。").FontSize(13).
			TextColor(t.TextMuted).Wrap().MaxWidth(460)
		ui.Text(c, "多个接入点可以填同一账号的不同网关，也可以填不同账号。").
			FontSize(13).TextColor(t.TextMuted).Wrap().MaxWidth(460)
		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "添加第一个接入点").Clicked() {
				a.openNewEditor()
			}
			if ui.Button(c, "导入同事分享").FontSize(11).Clicked() {
				a.openRelayImport()
			}
		})
	})
}

func (a *app) pointCard(c *ui.Context, v vpn.View) {
	t := c.Theme()
	card := ui.Column(c).Key("point:"+v.ID).Padding(10, 14).Gap(5).Radius(8).
		OnClick(func() { a.openEditor(v) })
	if card.Hovered() {
		card.Background(t.SurfaceHover)
	}
	if a.revealPointID == v.ID {
		card.ScrollIntoView()
		a.revealPointID = ""
	}
	card.Children(func() {
		a.pointHeading(c, v)
	})
}

func (a *app) pointHeading(c *ui.Context, v vpn.View) {
	t := c.Theme()
	addr := addrOf(v)
	if !a.simpleMode() {
		if sub := a.subtitleOf(v); sub != "" {
			addr += " · " + sub
		}
	}
	ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Column(c).Gap(2).Grow(1).MinWidth(0).Children(func() {
			ui.Text(c, v.Name).FontSize(14).Bold().Ellipsis("…").Tooltip(v.Name)
			ui.Text(c, addr).Font("monospace").FontSize(12).
				TextColor(t.TextMuted).Ellipsis("…").Tooltip(addr)
		})
		stateBadge(c, v.State.Label(), stateColor(t, v.State))
		a.pointAction(c, v)
	})
	if v.State == vpn.StateError && v.Error != "" {
		ui.Text(c, v.Error).FontSize(12).TextColor(t.Danger).Ellipsis("…").Tooltip(v.Error)
	} else if v.State == vpn.StateOnline && pointNeedsAttention(v) {
		ui.Text(c, "连接异常 · 点击卡片查看详情").FontSize(12).TextColor(t.Warning)
	}
}

func pointNeedsAttention(v vpn.View) bool {
	return v.TunnelState != "" || (v.MonitorOn && v.Alive == "已失效") ||
		v.DNSProbe.State == "failed" || v.TCPProbe.State == "failed"
}

func pointAlerts(c *ui.Context, v vpn.View) {
	t := c.Theme()
	if v.TunnelState != "" {
		colour := t.Warning
		label := "隧道保活探测失败"
		if v.TunnelFails > 0 {
			label += "（" + strconv.Itoa(v.TunnelFails) + " 次）"
		}
		if v.TunnelState == "dead" {
			colour = t.Danger
			label = "隧道已失效（登录仍有效），正在重建"
		}
		text := label
		if v.TunnelErr != "" {
			text += "：" + v.TunnelErr
		}
		ui.Text(c, text).FontSize(13).TextColor(colour).Wrap()
	}
	if v.DNSProbe.State == "failed" {
		ui.Text(c, healthProbeText("DNS", v.DNSProbe)).FontSize(12).TextColor(t.Warning).Wrap()
	}
	if v.TCPProbe.State == "failed" {
		ui.Text(c, healthProbeText("TCP", v.TCPProbe)).FontSize(12).TextColor(t.Warning).Wrap()
	}
}

func (a *app) pointFacts(c *ui.Context, v vpn.View) {
	t := c.Theme()
	ui.Row(c).GapX(14).GapY(4).Wrap().Children(func() {
		if v.ClientIP != "" {
			meta(c, t, "隧道 IP", v.ClientIP)
		}
		meta(c, t, "连接", fmt.Sprintf("%d 当前 / %d 累计", v.Active, v.Total))
		if len(v.Apps) > 0 {
			meta(c, t, "应用", fmt.Sprintf("%d 个", len(v.Apps)))
		}
		if v.Latency >= time.Millisecond {
			meta(c, t, "拨号延迟", v.Latency.Round(time.Millisecond).String())
		} else if v.LoginDuration >= time.Millisecond {
			meta(c, t, "登录耗时", v.LoginDuration.Round(time.Millisecond).String())
		}
		if v.Failed > 0 {
			meta(c, t, "失败", fmt.Sprintf("%d 次", v.Failed))
		}
		if v.InPool && !a.simpleMode() {
			meta(c, t, "统一入口", "参与分流")
		}
		if v.MonitorOn {
			state := v.Alive
			if state == "" {
				state = "待检测"
			}
			tone := t.TextMuted
			switch state {
			case "有效":
				tone = t.Success
			case "已失效":
				tone = t.Danger
			case "无法确认":
				tone = t.Warning
			}
			ui.Text(c, "会话监测："+state).FontSize(12).TextColor(tone).Tooltip(v.AliveErr)
		}
		for _, probe := range []struct {
			kind   string
			result vpn.ProbeResult
		}{{"DNS", v.DNSProbe}, {"TCP", v.TCPProbe}} {
			if probe.result.State != "failed" {
				ui.Text(c, healthProbeText(probe.kind, probe.result)).FontSize(12).TextColor(t.TextMuted).Wrap()
			}
		}
	})
	if summary := vpn.NodeSummary(v); len(summary) > 0 {
		line := "节点组 " + strings.Join(summary, " · ")
		ui.Text(c, line).FontSize(12).TextColor(t.TextMuted).Ellipsis("…").Tooltip(line)
	}
}

// disconnectPoint 停掉这个接入点上的本机项目再断开隧道：顺序不能反，
// 先断隧道会让还在跑的项目变成一堆失败日志。
func (a *app) disconnectPoint(id string) {
	go func() {
		a.localLife.Lock()
		defer a.localLife.Unlock()
		if a.local != nil {
			a.local.StopPoint(id)
		}
		a.mgr.Disconnect(id)
	}()
}

func (a *app) pointAction(c *ui.Context, v vpn.View) {
	switch v.State {
	case vpn.StateOnline:
		if ui.PrimaryButton(c, "代理浏览器").Label("代理浏览器 " + v.Name).FontSize(12).Clicked() {
			if err := openProxyBrowser(a.proxyFor(v.ID), "about:blank"); err != nil {
				a.setToast(err.Error())
			}
		}
		if ui.Button(c, "断开").Label("断开 " + v.Name).FontSize(12).Clicked() {
			a.disconnectPoint(v.ID)
		}
	case vpn.StateConnecting:
		if ui.Button(c, "取消").Label("取消 " + v.Name).FontSize(12).Clicked() {
			go a.mgr.Disconnect(v.ID)
		}
	default:
		// One button, and the configured auth mode decides what it does:
		// password logs in by itself, WeCom opens the QR popup, single
		// sign-on needs the browser.
		if ui.PrimaryButton(c, "登录").Label("登录 " + v.Name).FontSize(12).Clicked() {
			a.tunLogf("登录点击：%s（%s）", v.Name, v.ID)
			a.mgr.Connect(v.ID)
		}
	}
}

func (a *app) logPanel(c *ui.Context) {
	t := c.Theme()
	// 复制拿全部，排版只取最近 60 行：跑流量时日志每秒几十条，
	// 把 200 行全排版一遍的代价比它看起来贵得多。
	all := a.bus.Tail(logCopyLimit)
	entries := lastEntries(all, logRenderLimit)
	ui.Column(c).Gap(6).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			summary := fmt.Sprintf("最近 %d 条", len(entries))
			if len(all) > len(entries) {
				summary = fmt.Sprintf("显示最近 %d 条，共 %d 条", len(entries), len(all))
			}
			ui.Text(c, summary).FontSize(11).
				TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			if ui.Button(c, "复制全部").Label("复制全部日志").FontSize(11).Clicked() {
				var b strings.Builder
				for _, e := range all {
					fmt.Fprintf(&b, "%s [%s] %s\n", e.At.Format("15:04:05"), e.Source, e.Line)
				}
				a.copyText(b.String())
			}
			if ui.Button(c, "清空").FontSize(11).Clicked() {
				a.bus.Clear()
			}
		})
		box := ui.Scroll(c).Height(180).Radius(12).Border(1, t.Border).
			Background(t.Surface).Padding(10).ScrollbarInsets(6, 6, 6, 6)
		box.Children(func() {
			ui.Column(c).Gap(2).Children(func() {
				if len(entries) == 0 {
					ui.Text(c, "还没有日志。登录、断开和连接失败都会记在这里。").
						FontSize(11).TextColor(t.TextMuted)
					return
				}
				for _, e := range entries {
					ui.Row(c).Gap(8).AlignItems(ui.Start).Children(func() {
						ui.Text(c, e.At.Format("15:04:05")).Font("monospace").
							FontSize(11).TextColor(t.TextMuted)
						ui.Text(c, "["+e.Source+"]").Font("monospace").FontSize(11).
							TextColor(t.Accent)
						// 单行省略 + 悬停看全文：换行排版在长日志上是主要开销。
						ui.Text(c, e.Line).Font("monospace").FontSize(11).
							TextColor(t.Text).Grow(1).Ellipsis("…").Tooltip(e.Line)
					})
				}
			})
		})
	})
}

// accessSection shows the access log tab: each proxied target with the
// access point and application it went through.
func (a *app) accessSection(c *ui.Context) {
	t := c.Theme()
	var entries []vpn.LogEntry
	var succeeded, failed int
	for _, e := range a.bus.Tail(600) {
		switch e.Source {
		case vpn.AccessOK:
			succeeded++
		case vpn.AccessFail:
			failed++
		default:
			continue
		}
		entries = append(entries, e)
	}
	pageBar(c, "访问日志", fmt.Sprintf("%d 条", len(entries)), func() {
		if ui.Button(c, "复制全部").FontSize(12).Clicked() {
			var b strings.Builder
			for _, e := range entries {
				mark := "✔"
				if e.Source == vpn.AccessFail {
					mark = "✘"
				}
				fmt.Fprintf(&b, "%s %s %s\n", e.At.Format("15:04:05"), mark, e.Line)
			}
			a.copyText(b.String())
		}
		if ui.Button(c, "清空").FontSize(12).Clicked() {
			a.bus.ClearAccess()
			entries = nil
			succeeded, failed = 0, 0
		}
	})
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.Segmented(c, &a.accessFilter, "全部", "成功", "失败").Label("筛选访问结果")
		ui.Text(c, fmt.Sprintf("成功 %d · 失败 %d", succeeded, failed)).FontSize(12).TextColor(t.TextMuted)
	})
	// 无结果时也保留占满剩余空间的正文，避免底栏随列表收起。
	scroll := ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4)
	scroll.Children(func() {
		if len(entries) == 0 {
			noResults(c, "还没有访问记录", "启动本机项目或通过接入点访问内网后，连接结果会显示在这里。")
			return
		}
		if (a.accessFilter == 1 && succeeded == 0) || (a.accessFilter == 2 && failed == 0) {
			noResults(c, "没有符合筛选条件的记录", "切换到全部可以查看其他访问记录。")
			return
		}
		box := ui.Column(c).Padding(0, 10).Radius(8).Border(1, t.Border).
			Background(t.Surface)
		box.Children(func() {
			ui.Column(c).Children(func() {
				first := true
				for i := len(entries) - 1; i >= 0; i-- {
					e := entries[i]
					ok := e.Source == vpn.AccessOK
					if (a.accessFilter == 1 && !ok) || (a.accessFilter == 2 && ok) {
						continue
					}
					if !first {
						ui.Divider(c)
					}
					first = false
					ui.Row(c).Padding(7, 2).Gap(8).AlignItems(ui.Start).Children(func() {
						ui.Text(c, e.At.Format("15:04:05")).Font("monospace").
							FontSize(11).TextColor(t.TextMuted)
						tone, result := t.Danger, "失败"
						if ok {
							tone, result = t.Success, "成功"
						}
						ui.Text(c, result).FontSize(12).TextColor(tone)
						ui.Text(c, e.Line).FontSize(12).
							TextColor(t.Text).Grow(1).Wrap()
						if e.Route != nil && ui.Button(c, "详情").Label("路由详情 "+e.Line).FontSize(11).Clicked() {
							a.routeDetail = e.Route.Detail()
							a.routeDetailOpen = true
						}
					})
				}
			})
		})
	})
}

func logLabel(open bool) string {
	if open {
		return "收起运行日志"
	}
	return "查看运行日志"
}

// stateBadge draws a status as a tinted pill: the same hue as
// the status dot, at a tenth of its strength, so it never shouts.
func stateBadge(c *ui.Context, label string, colour ui.Color) {
	t := c.Theme()
	ui.Badge(c, label).
		Background(t.Surface.Mix(colour, 0.14)).
		TextColor(colour)
}

func stateColor(t *ui.Theme, state vpn.State) ui.Color {
	switch state {
	case vpn.StateOnline:
		return t.Success
	case vpn.StateConnecting:
		return t.Warning
	case vpn.StateError:
		return t.Danger
	default:
		return t.TextMuted
	}
}

func addrOf(v vpn.View) string {
	// A LAN relay node is reached as host:port over the share protocol, not as
	// an https:// gateway address; showing the latter would be wrong.
	if v.Protocol == model.ProtocolLANRelay {
		return net.JoinHostPort(v.Server, strconv.Itoa(v.Port))
	}
	return model.FormatAccessAddress(v.Server, v.Port)
}

func (a *app) subtitleOf(v vpn.View) string {
	parts := []string{}
	switch model.AuthMode(v.AuthMode) {
	case model.AuthModeAuto:
		parts = append(parts, "自动识别（旧）")
	case model.AuthModeWeCom:
		parts = append(parts, "企业微信弹窗登录")
	case model.AuthModeSSO:
		parts = append(parts, "单点登录（浏览器）")
	default:
		if v.Username != "" {
			user := v.Username
			if v.LoginDomain != "" {
				user += "@" + v.LoginDomain
			}
			parts = append(parts, user)
		}
	}
	// 简单模式只有一个代理地址，独立端口连提都不用提。
	if v.AutoConnect {
		parts = append(parts, "启动时自动登录")
	}
	return strings.Join(parts, " · ")
}

func displayAddr(addr string) string {
	return strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
}
