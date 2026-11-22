package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// tileAction 是快捷入口上的就地操作。
type tileAction struct {
	label string
	run   func()
}

type quickTile struct {
	label   string
	hint    string
	open    func()
	actions []tileAction
}

// quickTiles 收集当前在用的入口：在线接入点 + 运行中的本机项目。
func (a *app) quickTiles() []quickTile {
	var tiles []quickTile
	for _, v := range a.mgr.Views() {
		if v.State != vpn.StateOnline {
			continue
		}
		id := v.ID
		name := v.Name
		tiles = append(tiles, quickTile{
			label: name,
			hint:  "在线 · " + v.Protocol,
			open: func() {
				a.pointDiagnosticsID = id
				a.revealPointID = id
				a.goTab(0)
			},
			actions: []tileAction{{
				label: "断开 " + name,
				run:   func() { a.disconnectPoint(id) },
			}},
		})
	}
	for _, app := range a.cfg.LocalApps {
		view := a.localView(app.ID)
		if !view.Running {
			continue
		}
		appID := app.ID
		appName := app.Name
		tile := quickTile{
			label: appName,
			hint:  "本机项目运行中",
			open:  func() { a.goTab(3) },
		}
		if app.Mode == model.LocalAppBrowser {
			// 浏览器在独立窗口里关，项目名已经是查看入口。
			tile.hint = "浏览器窗口中运行"
		} else {
			tile.actions = []tileAction{{
				label: "停止 " + appName,
				run:   func() { go func() { _ = a.local.Stop(appID) }() },
			}}
		}
		tiles = append(tiles, tile)
	}
	return tiles
}

// quickLaunch 只展示正在使用的入口，避免离线时占用列表空间。
func (a *app) quickLaunch(c *ui.Context) {
	t := c.Theme()
	tiles := a.quickTiles()
	if len(tiles) == 0 {
		return
	}
	ui.Row(c).AlignItems(ui.Center).GapX(8).GapY(4).Wrap().Children(func() {
		ui.Text(c, "常用入口").FontSize(12).Bold().TextColor(t.TextMuted)
		for _, tile := range tiles {
			item := ui.Row(c).MaxWidth(225).Padding(2, 4).Radius(8).Gap(3).AlignItems(ui.Center).
				Background(t.Surface).Border(1, t.Border)
			item.Children(func() {
				if ui.Button(c, shortText(tile.label, 10)).Label("打开常用入口 " + tile.label).
					FontSize(12).Tooltip(tile.label + " · " + tile.hint).Clicked() {
					tile.open()
				}
				for _, action := range tile.actions {
					if ui.Button(c, shortActionLabel(action.label)).Label("常用入口：" + action.label).
						FontSize(12).Clicked() {
						action.run()
						a.invalidate()
					}
				}
			})
		}
	})
}

// shortActionLabel 把「断开 公司主网关」这类标签收成按钮上显示的动作。
func shortActionLabel(label string) string {
	if i := strings.Index(label, " "); i > 0 {
		return label[:i]
	}
	return label
}

// useProtocolGroups 决定要不要按协议分组：接入点很少、且只有一个协议时，
// 一个组头只挂一两张卡片反而琐碎，这时直接平铺。
func useProtocolGroups(views []vpn.View) bool {
	if len(views) <= 2 {
		for _, v := range views {
			if v.Protocol != views[0].Protocol {
				return true
			}
		}
		return false
	}
	return true
}

// pointsPanel 是一块发丝分隔的列表面板。
func (a *app) pointsPanel(c *ui.Context, views []vpn.View) {
	t := c.Theme()
	panel := ui.Column(c).Radius(8).Background(t.Surface).Border(1, t.Border)
	panel.Children(func() {
		for i, v := range views {
			if i > 0 {
				ui.Divider(c)
			}
			a.pointCard(c, v)
		}
	})
}

// groupedPoints 把接入点按协议分组；入口很少时退化成一块平铺列表。
func (a *app) groupedPoints(c *ui.Context, views []vpn.View) {
	if !useProtocolGroups(views) {
		a.pointsPanel(c, views)
		return
	}
	t := c.Theme()
	byProto := map[string][]vpn.View{}
	for _, v := range views {
		byProto[v.Protocol] = append(byProto[v.Protocol], v)
	}
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, proto := range protos {
		group := byProto[proto]
		label := proto
		if label == "" {
			label = "其他接入点"
		}
		ui.Row(c).AlignItems(ui.Center).Gap(8).Padding(4, 2).Children(func() {
			ui.Text(c, label).FontSize(12).Bold().TextColor(t.TextMuted)
			ui.Text(c, fmt.Sprintf("%d 个", len(group))).FontSize(12).TextColor(t.TextMuted)
		})
		a.pointsPanel(c, group)
	}
}

// envStrip 是页面底部的「运行环境」：只报事实，不放接管控件——
// 接管方式属于顶栏，两处都写会让同一件事有两个入口。
func (a *app) envStrip(c *ui.Context) {
	t := c.Theme()
	agg := a.mgr.Aggregate()
	running := 0
	for _, p := range a.cfg.LocalApps {
		if a.localView(p.ID).Running {
			running++
		}
	}
	ui.Divider(c)
	ui.Row(c).AlignItems(ui.Center).Gap(14).Padding(2, 4).Children(func() {
		listening := agg.Running && agg.Addr != ""
		if listening || a.sysProxyOn.Load() {
			ui.Row(c).AlignItems(ui.Center).Gap(6).Children(func() {
				ui.Text(c, "统一入口").FontSize(12).Bold()
				switch {
				case listening:
					addr := "socks5://" + displayAddr(agg.Addr)
					ui.Text(c, addr).Font("monospace").FontSize(12).TextColor(t.TextMuted)
					iconButton(c, copyIcon, "复制统一入口地址", func() { a.copyText(addr) })
				case agg.Error != "":
					ui.Text(c, "监听失败").FontSize(12).TextColor(t.Danger).Tooltip(agg.Error)
				default:
					ui.Text(c, "未启动").FontSize(12).TextColor(t.TextMuted)
				}
			})
		}
		ui.Row(c).Grow(1)
		ui.Text(c, fmt.Sprintf("本机项目 %d 个运行中", running)).FontSize(12).TextColor(t.TextMuted)
	})
}

// launcherBody 是启动台的正文：接入点页 = 常用入口 + 分组列表，其余页面单栏。
func (a *app) launcherBody(c *ui.Context) {
	if a.settings.open {
		a.settingsPage(c)
		return
	}
	switch a.tab {
	case 1:
		a.appsSection(c)
	case 2:
		a.accessSection(c)
	case 3:
		if a.simpleMode() {
			// 简单模式下「本机软件」收成「内网网站」：一个地址输入框加几个磁贴。
			a.sitesPage(c)
			return
		}
		a.localAppsSection(c)
	default:
		views := a.mgr.Views()
		// 简单模式：一个接入点时首屏就是一张卡，还没有点时只有添加引导；
		// 多个点时单卡描述不了复数，退回下面的列表。
		if a.simpleMode() {
			switch len(views) {
			case 0:
				a.simpleEmpty(c)
				return
			case 1:
				a.simpleHome(c, views[0])
				return
			}
		}
		ui.Column(c).Grow(1).MinHeight(0).Gap(12).Children(func() {
			pageBar(c, "接入点", fmt.Sprintf("%d 个", len(views)), func() {
				if len(views) > 0 {
					if ui.Button(c, "全部登录").Label("全部接入点重新登录").FontSize(12).Clicked() {
						a.mgr.ConnectAll(false)
					}
				}
			})
			ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(6, 2, 6, 0).Children(func() {
				ui.Column(c).Padding(0, 2, 0, 4).Gap(10).Children(func() {
					a.quickLaunch(c)
					if len(views) == 0 {
						a.emptyState(c)
						return
					}
					a.statusBanner(c, views)
					a.groupedPoints(c, views)
					a.recentFailures(c)
				})
			})
		})
	}
}
