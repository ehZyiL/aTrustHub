package main

import (
	"fmt"
	"sort"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/vpn"
)

// 这一版对应原型 C「场景启动台」：暗色、横向导航，首屏先给一排「常用入口」，
// 再把接入点按网关分组摊开，底部一条环境状态。原型把它定位成“固定工作流的
// 一键入口”，所以这里的取舍是：顶部永远有能直接点的入口，配置信息往下压。

// quickLaunch 是首屏的常用入口：在线接入点 + 运行中的本机项目。
func (a *app) quickLaunch(c *ui.Context) {
	t := c.Theme()
	type entry struct {
		label string
		hint  string
		open  func()
	}
	var items []entry
	for _, v := range a.mgr.Views() {
		if v.State != vpn.StateOnline {
			continue
		}
		id := v.ID
		items = append(items, entry{
			label: v.Name,
			hint:  "在线 · " + v.Protocol,
			open: func() {
				a.detailPointID = id
				a.tab = 0
				a.settings.open = false
			},
		})
	}
	for _, p := range a.cfg.LocalApps {
		if !a.localView(p.ID).Running {
			continue
		}
		items = append(items, entry{
			label: p.Name,
			hint:  "本机项目运行中",
			open: func() {
				a.tab = 3
				a.settings.open = false
			},
		})
	}
	ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Text(c, "常用入口").FontSize(13).Bold()
		ui.Text(c, "一键回到正在用的入口").FontSize(10).TextColor(t.TextMuted)
	})
	if len(items) == 0 {
		panel := ui.Column(c).Padding(16).Gap(4).Radius(14).
			Background(t.Surface).Border(1, t.Border)
		panel.Children(func() {
			ui.Text(c, "还没有在用的入口").FontSize(13).Bold()
			ui.Text(c, "登录一个接入点之后，它会出现在这里。").
				FontSize(11).TextColor(t.TextMuted)
		})
		return
	}
	ui.Row(c).Gap(8).Wrap().Children(func() {
		for _, item := range items {
			it := item
			ui.Column(c).Width(196).Padding(10, 12).Radius(14).Gap(2).
				Background(t.Surface).Border(1, t.Border).
				OnClick(func() {
					it.open()
					a.invalidate()
				}).Children(func() {
				ui.Text(c, it.label).FontSize(13).Bold().Ellipsis("…")
				ui.Text(c, it.hint).FontSize(10).TextColor(t.TextMuted).Ellipsis("…")
			})
		}
	})
}

// groupedPoints 把接入点按协议分组：每组一个头，组内还是行式列表。
func (a *app) groupedPoints(c *ui.Context, views []vpn.View) {
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
			ui.Text(c, label).FontSize(11).Bold().TextColor(t.TextMuted)
			ui.Text(c, fmt.Sprintf("%d 个", len(group))).FontSize(10).TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			ui.Column(c).Width(24).Height(1).Background(t.Border)
		})
		panel := ui.Column(c).Radius(14).Background(t.Surface).Border(1, t.Border)
		panel.Children(func() {
			for i, v := range group {
				if i > 0 {
					ui.Divider(c)
				}
				a.pointCard(c, v)
			}
		})
	}
}

// envStrip 是页面底部的环境状态：在线数、统一入口、接管方式、助手。
func (a *app) envStrip(c *ui.Context) {
	t := c.Theme()
	online, connecting, total := a.mgr.Counts()
	agg := a.mgr.Aggregate()
	entry := "未启动"
	entryLabel := "本机入口"
	if agg.Running && agg.Addr != "" {
		entry = agg.Addr
		// 只有真的在监听时才叫「统一入口」。
		entryLabel = "统一入口"
	}
	helper := "未启用"
	if captureExperimentEnabled() {
		helper = "已安装网络助手" // 入口文案统一放在设置页，这里只报状态。
	}
	ui.Row(c).AlignItems(ui.Center).Gap(16).Padding(8, 10).Radius(14).
		Background(t.Surface).Border(1, t.Border).Children(func() {
		ui.Text(c, "环境状态").FontSize(10).Bold().TextColor(t.TextMuted)
		ui.Text(c, fmt.Sprintf("接入点 %d / %d", online, total)).FontSize(11)
		if connecting > 0 {
			ui.Text(c, fmt.Sprintf("接入中 %d", connecting)).FontSize(11).TextColor(t.Warning)
		}
		ui.Text(c, entryLabel+" "+entry).Font("monospace").FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, "接管 "+a.captureMode()).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, "助手 "+helper).FontSize(11).TextColor(t.TextMuted)
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
		a.localAppsSection(c)
	default:
		views := a.mgr.Views()
		ui.Column(c).Grow(1).MinHeight(0).Gap(12).Children(func() {
			pageBar(c, "接入点", fmt.Sprintf("%d 个", len(views)), func() {
				if len(views) > 0 {
					if ui.Button(c, "全部登录").Label("全部接入点重新登录").FontSize(11).Clicked() {
						a.mgr.ConnectAll(false)
					}
				}
			})
			a.quickLaunch(c)
			ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
				ui.Column(c).Gap(12).Children(func() {
					a.statusBanner(c, views)
					if len(views) == 0 {
						a.emptyState(c)
						return
					}
					a.groupedPoints(c, views)
					a.recentFailures(c)
				})
			})
		})
	}
}
