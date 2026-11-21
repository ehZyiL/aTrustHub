package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// 这一版对应原型 C「场景启动台」，按评审意见再收一遍：
//   - 底栏只报运行环境，接管控件留在顶栏，避免两处说同一件事；
//   - 接入点很少且同协议时不摆分组头，一个组头挂一张卡片太碎；
//   - 常用入口的磁贴带动作（断开 / 停止 / 查看），高频操作不用跳到第四页；
//   - 深色主题里只让「在线、选中、主按钮」用荧光绿，底色与悬停降饱和。

// tileAction 是磁贴上就地可做的一件事。
type tileAction struct {
	label   string
	primary bool
	run     func()
}

// quickTile 是常用入口里的一格。
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
				a.detailPointID = id
				a.goTab(0)
			},
			actions: []tileAction{{
				label: "断开 " + name,
				run:   func() { go a.mgr.Disconnect(id) },
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
			// 浏览器在独立窗口里关，这里只做定位，不提供停止。
			tile.hint = "浏览器窗口中运行"
			tile.actions = []tileAction{{
				label: "查看 " + appName,
				run:   func() { a.goTab(3) },
			}}
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

// quickLaunch 是首屏的常用入口：磁贴上直接能做完常见的下一步。
func (a *app) quickLaunch(c *ui.Context) {
	t := c.Theme()
	tiles := a.quickTiles()
	ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Text(c, "常用入口").FontSize(13).Bold()
		ui.Text(c, "一边看状态，一边就能动").FontSize(10).TextColor(t.TextMuted)
	})
	if len(tiles) == 0 {
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
		for _, tile := range tiles {
			it := tile
			card := ui.Column(c).Width(204).Padding(10, 12).Radius(14).Gap(3).
				Background(t.Surface).Border(1, t.Border)
			card.OnClick(func() {
				it.open()
				a.invalidate()
			})
			card.Children(func() {
				ui.Text(c, it.label).FontSize(13).Bold().Ellipsis("…")
				ui.Text(c, it.hint).FontSize(10).TextColor(t.TextMuted).Ellipsis("…")
				if len(it.actions) > 0 {
					ui.Row(c).Gap(6).Padding(2, 0).Children(func() {
						for _, act := range it.actions {
							action := act
							var clicked bool
							if action.primary {
								clicked = ui.PrimaryButton(c, shortActionLabel(action.label)).
									Label(action.label).FontSize(11).Clicked()
							} else {
								clicked = ui.Button(c, shortActionLabel(action.label)).
									Label(action.label).FontSize(11).Clicked()
							}
							if clicked {
								action.run()
								a.invalidate()
							}
						}
					})
				}
			})
		}
	})
}

// shortActionLabel 把「断开 公司主网关」这类带名字的标签收成磁贴上显示的两个字。
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
	panel := ui.Column(c).Radius(14).Background(t.Surface).Border(1, t.Border)
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
			ui.Text(c, label).FontSize(11).Bold().TextColor(t.TextMuted)
			ui.Text(c, fmt.Sprintf("%d 个", len(group))).FontSize(10).TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			ui.Column(c).Width(24).Height(1).Background(t.Border)
		})
		a.pointsPanel(c, group)
	}
}

// envStrip 是页面底部的「运行环境」：只报事实，不放接管控件——
// 接管方式属于顶栏，两处都写会让同一件事有两个入口。
func (a *app) envStrip(c *ui.Context) {
	t := c.Theme()
	online, connecting, total := a.mgr.Counts()
	agg := a.mgr.Aggregate()
	running := 0
	for _, p := range a.cfg.LocalApps {
		if a.localView(p.ID).Running {
			running++
		}
	}
	helper := "未启用"
	if captureExperimentEnabled() {
		helper = "已就绪"
	}
	ui.Row(c).AlignItems(ui.Center).Gap(16).Padding(8, 10).Radius(14).
		Background(t.Surface).Border(1, t.Border).Children(func() {
		ui.Text(c, "运行环境").FontSize(10).Bold().TextColor(t.TextMuted)
		ui.Text(c, fmt.Sprintf("在线 %d / %d", online, total)).FontSize(11)
		if connecting > 0 {
			ui.Text(c, fmt.Sprintf("接入中 %d", connecting)).FontSize(11).TextColor(t.Warning)
		}
		if agg.Running && agg.Addr != "" {
			ui.Text(c, "统一入口 "+"socks5://"+displayAddr(agg.Addr)).
				Font("monospace").FontSize(11).TextColor(t.TextMuted)
		} else {
			// 没有在监听就别叫它「统一入口」，免得空状态下承诺一个不存在的入口。
			ui.Text(c, "入口未启动").FontSize(11).TextColor(t.TextMuted)
		}
		ui.Text(c, fmt.Sprintf("本机项目 %d 个运行中", running)).FontSize(11).TextColor(t.TextMuted)
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
					if ui.Button(c, "全部登录").Label("全部接入点重新登录").FontSize(11).Clicked() {
						a.mgr.ConnectAll(false)
					}
				}
			})
			ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(6, 2, 6, 0).Children(func() {
				ui.Column(c).Padding(0, 14, 0, 0).Gap(12).Children(func() {
					a.quickLaunch(c)
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
