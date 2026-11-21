package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/store"
	"github.com/qy/easyconnect/internal/vpn"
)

// logIcon is a small document-with-lines glyph for the TUN log button.
// copyIcon is two overlapping sheets, for "copy this address".
var copyIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`))

// refreshIcon is the two-arrow refresh glyph used by aTrust's own console, for
// "check this session again".
var refreshIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 1024 1024" fill="currentColor"><path d="M168 504.2c1-43.7 10-86.1 26.9-126 17.3-41 42.1-77.7 73.7-109.4S337 212.3 378 195c42.4-17.9 87.4-27 133.9-27s91.5 9.1 133.8 27c40.9 17.3 77.7 42.1 109.3 73.8 9.9 9.9 19.2 20.4 27.8 31.4l-60.2 47c-5.3 4.1-3.5 12.5 3 14.1l175.7 43c5 1.2 9.9-2.6 9.9-7.7l0.8-180.9c0-6.7-7.7-10.5-12.9-6.3l-56.4 44.1C765.8 155.1 646.2 92 511.8 92 282.7 92 96.3 275.6 92 503.8c-0.1 4.5 3.5 8.2 8 8.2h60c4.4 0 7.9-3.5 8-7.8z m756 7.8h-60c-4.4 0-7.9 3.5-8 7.8-1 43.7-10 86.1-26.9 126-17.3 41-42.1 77.8-73.7 109.4S687 811.7 646 829c-42.4 17.9-87.4 27-133.9 27s-91.5-9.1-133.9-27c-40.9-17.3-77.7-42.1-109.3-73.8-9.9-9.9-19.2-20.4-27.8-31.4l60.2-47c5.3-4.1 3.5-12.5-3-14.1l-175.7-43c-5-1.2-9.9 2.6-9.9 7.7l-0.7 181c0 6.7 7.7 10.5 12.9 6.3l56.4-44.1C258.2 868.9 377.8 932 512.2 932c229.2 0 415.5-183.7 419.8-411.8 0.1-4.5-3.5-8.2-8-8.2z"/></svg>`))

// iconButton draws a small clickable glyph, the same shape as the TUN log
// button, so one-row actions do not take a full button's width.
func iconButton(c *ui.Context, icon *ui.SVG, tooltip string, onClick func()) {
	ui.Row(c).Padding(4).Radius(8).AlignItems(ui.Center).
		OnClick(onClick).Tooltip(tooltip).Children(func() {
		ui.Icon(c, icon).Size(15, 15)
	})
}

var logIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/></svg>`))

// view builds one frame of the window: the header, the aggregate proxy,
// the access points and their log.
// ---- 样式基准 ----
//
// 字号只有五档：10 状态栏、11 次要文字、13 正文、15 区块标题、18 应用名。
// 圆角只有四档：3/4 圆点、8 色块与芯片、12 面板与卡片、999 胶囊。
// 按钮：列表、卡片、弹窗内的动作 11；页面工具栏 13。
// 边框：面板一律 1px t.Border，面板内部靠 ui.Divider 分隔，不叠两层边框。
// 间距：窗口内边距 16；页面块间 10~12；卡片 14；列表行 10×12；弹窗内容 10。
// 滚动区：ScrollbarInsets(8,6,8,4)（弹窗正文用 6）；滑块 8 DIP、悬停才显示。
// 弹窗：dialogHeader + dialogFooter + 三档宽度，正文高度用 dialogBodyHeight 兜底。

// pageShortcuts 是 ⌘1–⌘4 对应的四个页面，顺序与分段导航一致。
var pageShortcuts = []ui.Key{ui.Key1, ui.Key2, ui.Key3, ui.Key4}

func (a *app) view(c *ui.Context) {
	// 主线程上用框架的可见性校正门控标记：藏在托盘时不再重建整树。
	a.syncWindowVisible()
	// 原型是暗色启动台，但颜色模式由设置里的偏好决定：
	// 跟随系统时听系统的，浅色 / 深色则把外观固定下来。
	c.SetTheme(a.appearanceTheme(c.Theme().Dark))
	t := c.Theme()
	if a.toast != "" {
		c.Toast(a.toast)
		a.toast = ""
	}
	root := ui.Column(c).Fill().Padding(16).Gap(10).Background(t.Background)
	if b := root.Bounds(); b.H > 0 {
		a.windowH = b.H
	}
	root.OnShortcut(ui.Cmd, ui.KeyN, a.openNewEditor)
	root.OnShortcut(ui.Cmd, ui.KeyR, func() { a.mgr.ConnectAll(false) })
	// ⌘1–⌘4 直接跳到四个页面，与分段导航和底部提示一致。
	for page, key := range pageShortcuts {
		root.OnShortcut(ui.Cmd, key, func() {
			a.goTab(page)
		})
	}
	root.Children(func() {
		a.toolbar(c)
		// 操作栏与内容之间一条发丝线。
		ui.Divider(c)
		a.launcherBody(c)
		if !a.settings.open {
			a.envStrip(c)
		}
	})
	// Esc 从设置页返回，和关闭弹窗的习惯一致。
	root.OnShortcut(0, ui.KeyEscape, func() {
		if a.settings.open {
			a.settings.open = false
			a.invalidate()
		}
	})
	a.editorView(c)
	a.dnsProbeView(c)
	a.routesView(c)
	if a.routeDetailOpen {
		ui.Modal(c, &a.routeDetailOpen, func() {
			ui.Column(c).Width(dialogWide).Gap(10).Children(func() {
				dialogHeader(c, "连接路由详情", "这一条请求为什么选了这个出口")
				ui.Text(c, a.routeDetail).FontSize(13).Wrap()
				dialogFooter(c, func() {
					ui.Row(c).Grow(1)
					if ui.Button(c, "关闭详情").FontSize(11).Clicked() {
						a.routeDetailOpen = false
					}
				})
			})
		})
	}
	a.deleteView(c)
	a.logoutView(c)
	a.quitView(c)
	a.appDetailView(c)
	a.authenticationView(c)
	a.localAppEditorView(c)
	a.localAppDeleteView(c)
	a.certificateProbeView(c)
}

// qrCard was removed: WeCom's QR login now uses a WebView popup.

func accessTabLabel() string {
	return "访问日志"
}

func appTabLabel(n int) string {
	if n > 0 {
		return fmt.Sprintf("网关资源 %d", n)
	}
	return "网关资源"
}

// appEntry is one application of one online access point.
type appEntry struct {
	PointID   string
	PointName string
	App       vpn.App
}

// allApps returns the applications of every online access point, in the
// access points' order.
func (a *app) allApps() []appEntry {
	var out []appEntry
	for _, v := range a.mgr.Views() {
		if v.State != vpn.StateOnline {
			continue
		}
		for _, app := range v.Apps {
			out = append(out, appEntry{PointID: v.ID, PointName: v.Name, App: app})
		}
	}
	return out
}

func (a *app) appCount() int {
	n := 0
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline {
			n += len(v.Apps)
		}
	}
	return n
}

func (a *app) appsSection(c *ui.Context) {
	t := c.Theme()
	all := a.allApps()
	query := strings.ToLower(strings.TrimSpace(a.appQuery))
	shown := make([]appEntry, 0, len(all))
	for _, entry := range all {
		if query != "" && !appMatches(entry, query) {
			continue
		}
		switch a.appFilter {
		case "on":
			if !a.appEnabled(entry.PointID, entry.App.ID) {
				continue
			}
		case "off":
			if a.appEnabled(entry.PointID, entry.App.ID) {
				continue
			}
		}
		shown = append(shown, entry)
	}

	pageBar(c, "网关资源", fmt.Sprintf("%d 个", len(all)), func() {
		if ui.Button(c, "网络授权与路由").Clicked() {
			a.openRoutes()
		}
		// 只看已启用 / 未启用的应用，排查时不用在 158 个里翻。
		ui.Segmented(c, &a.appFilterIndex, "所有", "已启用", "未启用").
			Label("过滤资源")
		a.appFilter = appFilterValue(a.appFilterIndex)
		ui.SearchField(c, &a.appQuery).Placeholder("搜索资源名称、地址或标签").
			Label("搜索资源").Width(240)
	})

	scroll := ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4)
	scroll.Children(func() {
		ui.Column(c).Gap(14).Children(func() {
			if len(all) == 0 {
				a.appsEmpty(c)
				return
			}
			if len(shown) == 0 {
				noResults(c, "没有匹配「"+a.appQuery+"」的应用",
					"换个名称、地址或标签试试；清空搜索可以看到全部应用。")
				return
			}
			// Group by access point, in the order the points appear.
			var order []string
			groups := map[string][]appEntry{}
			names := map[string]string{}
			for _, entry := range shown {
				if _, ok := groups[entry.PointID]; !ok {
					order = append(order, entry.PointID)
				}
				groups[entry.PointID] = append(groups[entry.PointID], entry)
				names[entry.PointID] = entry.PointName
			}
			if a.appCollapsed == nil {
				a.appCollapsed = map[string]bool{}
			}
			for _, pid := range order {
				entries := groups[pid]
				collapsed := a.appCollapsed[pid]
				ui.Column(c).Gap(8).Children(func() {
					// 一组资源装在一个面板里：分组头是面板顶部的一条色带，行间用发丝分隔。
					panel := ui.Column(c).Radius(12).Border(1, t.Border).
						Background(t.Surface)
					panel.Children(func() {
						a.appGroupHeader(c, pid, names[pid], len(entries), collapsed)
						if collapsed {
							return
						}
						for _, entry := range entries {
							ui.Divider(c)
							a.appRow(c, entry)
						}
					})
				})
			}
		})
	})
}

func (a *app) appsEmpty(c *ui.Context) {
	t := c.Theme()
	online, _, _ := a.mgr.Counts()
	card := ui.Column(c).Padding(32).Gap(10).Center().Radius(12).
		Border(1, t.Border).Background(t.Surface)
	card.Children(func() {
		if online == 0 {
			ui.Text(c, "还没有登录的接入点").FontSize(15).Bold()
			ui.Text(c, "登录后，服务器下发的应用会显示在这里；"+
				"隧道应用沿用登录后的分流规则。").FontSize(13).TextColor(t.TextMuted).
				Wrap().MaxWidth(460)
			if ui.PrimaryButton(c, "去登录接入点").Clicked() {
				a.tab = 0
			}
			return
		}
		ui.Text(c, "已登录，服务器没有下发应用").FontSize(15).Bold()
		ui.Text(c, "此页显示网关资源。EasyConnect 目前请在接入点页面启动代理浏览器，或为软件填写代理地址。").
			FontSize(13).TextColor(t.TextMuted).Wrap().MaxWidth(460)
	})
}

// appTunnelSwitch 画单个资源的「隧道代理」开关，卡片与行式列表共用。
func (a *app) appTunnelSwitch(c *ui.Context, entry appEntry) {
	t := c.Theme()
	app := entry.App
	ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "隧道代理").FontSize(11).TextColor(t.TextMuted)
		// 开关必须绑定到堆上的稳定变量：绑局部变量时点击写回的是
		// 已经失效的地址，状态既不会保存也不会还原。
		key := entry.PointID + "/" + app.ID
		on := a.appEnabled(entry.PointID, app.ID)
		sw, ok := a.appSwitch[key]
		if !ok {
			v := on
			sw = &v
			if a.appSwitch == nil {
				a.appSwitch = map[string]*bool{}
			}
			a.appSwitch[key] = sw
		}
		ui.Switch(c, sw).Label("隧道代理 " + app.Name).OnChange(func() {
			a.setAppEnabled(entry.PointID, app.ID, *sw)
		})
	})
}

// groupBar 画分组头共用的那一行：折叠箭头、可选状态灯、名称、可选状态文字、
// 计数和右侧动作。资源分组与本机项目分组都用它，两处形状不会走样。
func groupBar(c *ui.Context, collapsed bool, dot ui.Color, name, status, count string, onToggle func(), trailing func()) {
	t := c.Theme()
	arrow := "▾"
	if collapsed {
		arrow = "▸"
	}
	bar := ui.Row(c).Padding(8, 12).Gap(8).AlignItems(ui.Center).Background(t.Background)
	bar.OnClick(onToggle)
	bar.Children(func() {
		ui.Text(c, arrow).FontSize(11).TextColor(t.TextMuted)
		if dot != ui.Transparent {
			ui.Row(c).Size(6, 6).Radius(3).Background(dot)
		}
		ui.Text(c, name).FontSize(13).Bold().Ellipsis("…")
		if status != "" {
			ui.Text(c, status).FontSize(11).TextColor(t.TextMuted)
		}
		ui.Row(c).Grow(1)
		ui.Text(c, count).FontSize(11).TextColor(t.TextMuted)
		if trailing != nil {
			trailing()
		}
	})
}

// appGroupHeader 是资源分组头：网关名、资源数，右侧整组启停。
func (a *app) appGroupHeader(c *ui.Context, pid, name string, count int, collapsed bool) {
	groupBar(c, collapsed, ui.Transparent, name, "", fmt.Sprintf("%d 个应用", count), func() {
		if a.appCollapsed == nil {
			a.appCollapsed = map[string]bool{}
		}
		a.appCollapsed[pid] = !collapsed
		a.invalidate()
	}, func() {
		if ui.Button(c, "启用所有").Label("启用所有 " + name).FontSize(11).Clicked() {
			a.setAllAppsEnabled(pid, true)
		}
		if ui.Button(c, "停用所有").Label("停用所有 " + name).FontSize(11).Clicked() {
			a.setAllAppsEnabled(pid, false)
		}
	})
}

// appMark 画资源行首的字母色块：浅底 + 细描边 + 同色字母，比实心色块安静。
func appMark(c *ui.Context, t *ui.Theme, name string) {
	ui.Row(c).Size(28, 28).Radius(9).Background(t.Surface).Border(1, t.Border).
		AlignItems(ui.Center).Justify(ui.Center).Children(func() {
		ui.Text(c, firstRune(name)).FontSize(13).Bold().
			TextColor(glyphColor(t, name))
	})
}

// appRow 是资源页的一行：字母槽、名称与地址、类型、隧道代理开关和详情入口。
// 行式密度让上百个资源能一屏扫过；分类、描述与停用状态都挤在副标题里。
func (a *app) appRow(c *ui.Context, entry appEntry) {
	t := c.Theme()
	app := entry.App
	enabled := a.appEnabled(entry.PointID, app.ID)
	row := ui.Row(c).Padding(12, 14).Gap(10).AlignItems(ui.Center).Radius(8)
	// 悬停时整行轻轻抬起：列表因此有“可以点”的手感。
	if row.Hovered() {
		row = row.Background(t.SurfaceHover)
	}
	row.Children(func() {
		appMark(c, t, app.Name)
		ui.Column(c).Gap(2).Grow(1).MinWidth(0).Children(func() {
			ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
				ui.Text(c, app.Name).FontSize(13).Bold().Ellipsis("…")
				if !enabled {
					ui.Text(c, "已停用代理").FontSize(11).TextColor(t.Danger)
				}
			})
			sub := app.AddressSummary()
			if app.GroupName != "" {
				sub = app.GroupName + " · " + sub
			}
			if app.Description != "" {
				sub += " · " + app.Description
			}
			ui.Text(c, sub).FontSize(11).
				TextColor(t.TextMuted).Ellipsis("…")
		})
		ui.Text(c, app.TypeLabel()).FontSize(11).TextColor(t.TextMuted)
		a.appTunnelSwitch(c, entry)
		if ui.Button(c, "详情").Label("应用详情 " + app.Name).FontSize(11).Clicked() {
			a.openAppDetail(entry)
		}
	})
}

func (a *app) openAppDetail(entry appEntry) {
	a.detailApp = entry.App
	a.detailPoint = entry.PointName
	a.detailPointID = entry.PointID
	a.appTestFor = ""
	a.appTestMsg = ""
	a.appTesting = false
	a.detailOpen = true
}

func (a *app) appDetailView(c *ui.Context) {
	if !a.detailOpen {
		return
	}
	t := c.Theme()
	app := a.detailApp
	ui.Modal(c, &a.detailOpen, func() {
		ui.Column(c).Width(dialogRegular).Gap(10).Children(func() {
			dialogHeader(c, "应用详情", app.Name+" · "+a.detailPoint)
			ui.Field(c, "应用名称", func() { ui.Text(c, app.Name).FontSize(13) })
			ui.Field(c, "描述", func() {
				desc := app.Description
				if desc == "" {
					desc = "—"
				}
				ui.Text(c, desc).FontSize(13)
			})
			ui.Field(c, "应用类型", func() { ui.Text(c, app.TypeLabel()).FontSize(13) })
			if app.GroupName != "" {
				ui.Field(c, "分类", func() { ui.Text(c, app.GroupName).FontSize(13) })
			}
			if app.NodeGroupName != "" || app.NodeGroupID != "" {
				node := app.NodeGroupName
				if node == "" {
					node = app.NodeGroupID
				}
				ui.Field(c, "节点组", func() { ui.Text(c, node).FontSize(13) })
			}
			if len(app.Addresses) > 0 || app.AppAddress != "" || app.AccessAddress != "" {
				ui.Field(c, "服务器地址", func() {
					ui.Scroll(c).MaxHeight(92).Children(func() {
						ui.Column(c).Gap(4).Children(func() {
							for _, line := range app.AddressLines() {
								ui.Text(c, line).Font("monospace").FontSize(13)
							}
						})
					})
					if ui.Button(c, "复制全部地址").FontSize(11).Clicked() {
						a.copyText(strings.Join(app.AddressLines(), "\n"))
					}
				})
			}
			if app.Host() != "" {
				ui.Field(c, "访问方式", func() {
					ui.Column(c).Gap(6).Children(func() {
						proxy := a.proxyFor(a.detailPointID)
						if proxy != "" {
							ui.Text(c, "这是隧道应用，需要用本应用的代理访问（SOCKS5 或 HTTP）："+proxy).
								FontSize(13)
							ui.Text(c, "浏览器里代理协议建议选 HTTP（其次 SOCKS5），地址端口用上面这个，再打开该地址。").
								FontSize(11).TextColor(t.TextMuted)
							ui.Row(c).Gap(8).Children(func() {
								if ui.Button(c, "复制代理").FontSize(11).Clicked() {
									a.copyText(proxy)
								}
								if ui.Button(c, "测试全部地址").FontSize(11).Disabled(a.appTesting).Clicked() {
									a.testAppConnectivity(app)
								}
								if ui.Button(c, "用代理浏览器打开").FontSize(11).Clicked() {
									if err := openProxyBrowser(proxy, appOpenURL(app)); err != nil {
										a.copyText(proxyBrowserCommand(proxy, appOpenURL(app)))
										a.toast = "没能直接启动浏览器，已复制命令：" + err.Error()
									}
								}
							})
							if a.appTestMsg != "" {
								ui.Scroll(c).MaxHeight(66).Children(func() {
									ui.Column(c).Gap(1).Children(func() {
										for _, line := range strings.Split(a.appTestMsg, "\n") {
											if line == "" {
												continue
											}
											col := t.TextMuted
											if strings.HasPrefix(line, "✅") {
												col = t.Success
											} else if strings.HasPrefix(line, "❌") {
												col = t.Danger
											}
											ui.Text(c, line).FontSize(11).TextColor(col)
										}
									})
								})
							}
						} else {
							ui.Text(c, "接入点在线后，用本应用的 SOCKS5 代理访问。").
								FontSize(11).TextColor(t.TextMuted)
						}
					})
				})
			}
			if app.AccessEntry != "" {
				ui.Field(c, "浏览器打开地址", func() {
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, app.AccessEntry).FontSize(11).Grow(1).Ellipsis("…")
						if ui.Button(c, "打开").FontSize(11).Clicked() {
							if err := mygo.Shell.OpenExternal(app.AccessEntry); err != nil {
								a.toast = "打不开地址：" + err.Error()
							}
						}
					})
				})
			}
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.PrimaryButton(c, "关闭").FontSize(11).Clicked() {
					a.detailOpen = false
				}
			})
		})
	})
}

func (a *app) proxyFor(pointID string) string {
	if p := a.cfg.Find(pointID); p != nil && p.SocksPort > 0 {
		return displayAddr(net.JoinHostPort(a.cfg.Settings.ListenHost, strconv.Itoa(p.SocksPort)))
	}
	if agg := a.mgr.Aggregate(); agg.Running && agg.Addr != "" {
		return displayAddr(agg.Addr)
	}
	return ""
}

// testAppConnectivity dials the app's backend through the tunnel and reports
// whether it is reachable, which separates a tunnel problem from a browser
// proxy that is not set.
func (a *app) testAppConnectivity(app vpn.App) {
	id := a.detailPointID
	ips := app.ProbeHosts()
	ports := app.TestPorts()
	if len(ips) == 0 || len(ports) == 0 {
		a.appTestMsg = "该应用没有可直接测试的地址"
		return
	}
	// Bound the work for large ranges.
	if len(ips) > 64 {
		ips = ips[:64]
	}
	if len(ips) > 24 && len(ports) > 5 {
		ports = ports[:5]
	}
	type hostJob struct {
		host  string
		ports []int
	}
	jobs := make([]hostJob, 0, len(ips))
	for _, ip := range ips {
		jobs = append(jobs, hostJob{host: ip, ports: ports})
	}
	a.appTesting = true
	a.appTestFor = id
	a.appTestMsg = fmt.Sprintf("正在测试 %d 个 IP…", len(jobs))
	a.invalidate()
	go func() {
		lines := make([]string, len(jobs))
		var wg sync.WaitGroup
		for i, j := range jobs {
			wg.Add(1)
			go func(i int, j hostJob) {
				defer wg.Done()
				lines[i] = a.probeHostText(id, j.host, j.ports)
			}(i, j)
		}
		wg.Wait()
		// 一个应用可能有多个地址：先给结论，再列明细，避免一条不通
		// 让人以为整个应用不可用。
		ok, total := 0, len(lines)
		for _, line := range lines {
			if strings.HasPrefix(line, "✅") {
				ok++
			}
		}
		summary := fmt.Sprintf("该应用可用：%d/%d 个地址可达", ok, total)
		if ok == 0 {
			summary = fmt.Sprintf("该应用当前不可用：%d 个地址都不可达", total)
		}
		body := summary + "\n" + strings.Join(lines, "\n")
		a.win.Update(func() {
			a.appTesting = false
			a.appTestMsg = body
		})
	}()
}

// probeHostText dials one host on its candidate ports (concurrently) through
// the tunnel and returns a one-line result.
func (a *app) probeHostText(id, host string, ports []int) string {
	if len(ports) == 0 {
		ports = []int{443, 80}
	}
	// 全局 TUN 接管时，本地的拨号在 TUN 栈里就完成了握手，测出来永远是
	// 「可达 2ms」。这时让 helper 用真实隧道连一次；helper 不支持时退回直连。
	if a.tunOn && hostInTun(a.tunPoints, id) {
		if point := a.cfg.Find(id); point != nil {
			for _, p := range ports {
				addr := net.JoinHostPort(host, strconv.Itoa(p))
				ok, ms, errText, answered, skip := a.probeTunnel(point.Name, addr, 2*time.Second)
				if !answered || skip {
					return a.directProbeText(id, host, ports)
				}
				if ok {
					return fmt.Sprintf("✅ %s 可达（%d ms，经隧道）", addr, ms)
				}
				if errText != "" {
					return fmt.Sprintf("❌ %s 不可达（%s）", addr, errText)
				}
			}
		}
	}
	return a.directProbeText(id, host, ports)
}

// directProbeText dials one host through the local dialer, which is all that is
// possible when the helper cannot answer probes.
func (a *app) directProbeText(id, host string, ports []int) string {
	if len(ports) == 0 {
		ports = []int{443, 80}
	}
	type result struct {
		port int
		d    time.Duration
		err  error
	}
	ch := make(chan result, len(ports))
	for _, p := range ports {
		go func(p int) {
			addr := net.JoinHostPort(host, strconv.Itoa(p))
			// The tunnel dialer may not honor its context when the backend
			// never answers (a silent SYN drop), so enforce the timeout here
			// too: a probe must always return, never leave the UI "测试中".
			type dialOut struct {
				d   time.Duration
				err error
			}
			out := make(chan dialOut, 1)
			go func() {
				d, err := a.mgr.TestDialTimeout(id, "tcp", addr, 2500*time.Millisecond)
				out <- dialOut{d: d, err: err}
			}()
			select {
			case o := <-out:
				ch <- result{port: p, d: o.d, err: o.err}
			case <-time.After(3 * time.Second):
				ch <- result{port: p, err: errors.New("连接超时")}
			}
		}(p)
	}
	var lastErr error
	for i := 0; i < len(ports); i++ {
		r := <-ch
		if r.err == nil {
			return fmt.Sprintf("✅ %s:%d 可达（%d ms）", host, r.port, r.d.Milliseconds())
		}
		lastErr = r.err
	}
	if len(ports) == 1 {
		return fmt.Sprintf("❌ %s:%d 不可达（%s）", host, ports[0], shortErr(lastErr))
	}
	return fmt.Sprintf("❌ %s 不可达（%s）", host, shortErr(lastErr))
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 60 {
		s = s[:60] + "…"
	}
	return s
}

func appMatches(entry appEntry, query string) bool {
	app := entry.App
	fields := []string{app.Name, app.Description, app.GroupName, app.NodeGroupName,
		entry.PointName, app.TypeLabel(), app.AppAddress, app.AccessAddress, app.AccessEntry}
	fields = append(fields, app.AddressLines()...)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return "应"
}

// gearIcon 是设置入口的齿轮。
var gearIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.56V21a2 2 0 1 1-4 0v-.11a1.7 1.7 0 0 0-1.11-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1H3a2 2 0 1 1 0-4h.11a1.7 1.7 0 0 0 1.56-1.11 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34H9a1.7 1.7 0 0 0 1-1.56V3a2 2 0 1 1 4 0v.11a1.7 1.7 0 0 0 1 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87V9a1.7 1.7 0 0 0 1.56 1H21a2 2 0 1 1 0 4h-.11a1.7 1.7 0 0 0-1.56 1z"/></svg>`))

// toolbar 是窗口顶部唯一的操作栏：品牌、页面导航、网络状态、设置与主操作全在一行。
// 全局 TUN / 系统代理这类开关不再堆在这里，而是放进设置页的「网络」分组，
// 顶栏只保留一个能看出当前接管方式、又能就地切换的入口。
func (a *app) toolbar(c *ui.Context) {
	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		if a.icon != nil {
			ui.Image(c, a.icon).Size(24, 24)
		}
		ui.Text(c, appName).FontSize(15).Bold()
		ui.Row(c).Grow(1)
		a.pageNav(c)
		a.captureChip(c)
		iconButton(c, gearIcon, "设置", func() { a.openSettingsAt(a.settings.section) })
		if ui.PrimaryButton(c, "＋ 接入点").Label("＋ 添加接入点").FontSize(11).Clicked() {
			a.openNewEditor()
		}
	})
}

// 接管方式的四个档位。系统代理、全局 TUN 与应用接管互斥，所以做成一个下拉。
const (
	captureOff        = "不使用"
	captureSystem     = "系统代理"
	captureGlobalTUN  = "全局 TUN"
	captureAppCapture = "应用接管"
)

// captureModes 是下拉里可选的值；应用接管只在支持的平台上出现。
func captureModes() []string {
	modes := []string{captureOff, captureSystem, captureGlobalTUN}
	if supportsResourceTUN() {
		modes = append(modes, captureAppCapture)
	}
	return modes
}

// captureMode 是当前真正生效的接管方式：先看应用接管，再看全局 TUN，最后系统代理。
func (a *app) captureMode() string {
	switch {
	case a.resourceTUNActive():
		return captureAppCapture
	case a.tunOn || a.tunPending:
		return captureGlobalTUN
	case a.sysProxyOn:
		return captureSystem
	}
	return captureOff
}

// applyCaptureMode 把接管方式切到 mode：先关闭其他两种，再开启所选的。
// 切换是异步的，界面状态每帧从实际状态回读，不依赖本地变量。
func (a *app) applyCaptureMode(mode string) {
	from := a.captureMode()
	if from == mode {
		return
	}
	// 先停掉不在目标里的接管方式。
	if from == captureAppCapture && a.resourceTUN != nil {
		a.resourceTUN.Stop()
	}
	if from == captureGlobalTUN {
		go a.stopTUNSerialized()
	}
	if from == captureSystem && supportsSystemProxy() {
		a.toggleSystemProxy()
	}
	switch mode {
	case captureSystem:
		if supportsSystemProxy() {
			a.toggleSystemProxy()
		}
	case captureGlobalTUN:
		if pid := a.firstOnlinePoint(); pid != "" {
			a.tunWanted = true
			go a.startTUNSerialized(pid)
		} else {
			a.toast = "没有在线接入点，先登录再开 TUN"
		}
	case captureAppCapture:
		a.setupResourceTUN()
		if a.resourceTUN != nil {
			if a.store != nil {
				if _, err := a.store.Update(func(cfg *model.Config) error { cfg.Settings.TunEnabled = false; return nil }); err != nil {
					a.toast = "保存接管模式失败：" + err.Error()
					return
				}
				_ = a.saveConfig()
			}
			a.resourceTUN.Start()
		}
	}
	a.invalidate()
}

// pageBar 是每个页面内容顶部的上下文栏：左边标题与计数，右边本页的过滤、搜索
// 与主操作。四个页面都用它，操作位置因此一致。
func pageBar(c *ui.Context, title, count string, trailing func()) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		ui.Text(c, title).FontSize(15).Bold()
		if count != "" {
			ui.Text(c, count).FontSize(11).TextColor(t.TextMuted)
		}
		ui.Row(c).Grow(1)
		trailing()
	})
}

// statusBanner 用一条横幅回答「内网现在能不能用」，并把统一入口、分流策略和
// 批量动作收进来，取代原先独占一块的统一入口卡片。
func (a *app) statusBanner(c *ui.Context, views []vpn.View) {
	t := c.Theme()
	online, connecting, total := a.mgr.Counts()
	agg := a.mgr.Aggregate()

	failed := 0
	firstErr := ""
	names := make([]string, 0, len(views))
	for _, v := range views {
		switch v.State {
		case vpn.StateOnline:
			label := v.Name
			if v.Latency >= time.Millisecond {
				label += " " + v.Latency.Round(time.Millisecond).String()
			}
			if len(names) < 3 {
				names = append(names, label)
			}
		case vpn.StateError:
			failed++
			if firstErr == "" {
				firstErr = v.Name
				if v.Error != "" {
					firstErr += "：" + v.Error
				}
			}
		}
	}

	dot := t.TextMuted
	title := "尚未连接内网"
	summary := fmt.Sprintf("%d 个接入点未连接，登录后即可使用代理浏览器与端口转发", total)
	if total == 0 {
		title = "内网尚未配置"
		summary = "先添加一个 EasyConnect / aTrust 网关，登录后即可使用代理浏览器与端口转发"
	}
	if online > 0 {
		dot = t.Success
		title = "内网现在可用"
		onlineNames := strings.Join(names, " · ")
		if online > len(names) {
			onlineNames += " 等"
		}
		summary = fmt.Sprintf("%d 个接入点在线（%s）", online, onlineNames)
	}
	if connecting > 0 {
		summary += fmt.Sprintf(" · %d 个正在连接", connecting)
	}
	if failed > 0 {
		summary += fmt.Sprintf(" · %d 个需要处理", failed)
	}

	card := ui.Column(c).Padding(12, 16).Gap(8).Radius(14).
		Background(t.Surface.Mix(t.Accent, 0.04)).Shadow(0, 2, 10, 0, cardShadow(t))
	card.Children(func() {
		// 一条裤要带上说完了：状态、在线情况、统一入口和批量动作。
		// 窗口窄时末尾的控件自动换行，不用另起一行版式。
		ui.Row(c).AlignItems(ui.Center).Gap(10).Wrap().Children(func() {
			ui.Row(c).Size(8, 8).Radius(4).Background(dot)
			ui.Text(c, title).FontSize(13).Bold()
			ui.Text(c, summary).FontSize(11).TextColor(t.TextMuted).
				Grow(1).MinWidth(0).Ellipsis("…")
			if a.sysProxyOn {
				if agg.Running {
					addr := "socks5://" + displayAddr(agg.Addr)
					ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
						ui.Text(c, "统一入口").FontSize(11).TextColor(t.TextMuted)
						ui.Text(c, addr).Font("monospace").FontSize(11).TextColor(t.Text)
						ui.Row(c).Padding(3).Radius(8).AlignItems(ui.Center).
							OnClick(func() { a.copyText(addr) }).
							Tooltip("复制统一入口地址").Children(func() {
							ui.Icon(c, copyIcon).Size(12, 12)
						})
					})
				} else if agg.Error != "" {
					ui.Text(c, "统一入口未监听："+agg.Error).FontSize(11).
						TextColor(t.Danger).MaxWidth(200).Ellipsis("…").Tooltip(agg.Error)
				} else {
					ui.Text(c, "统一入口未开启").FontSize(11).TextColor(t.TextMuted)
				}
				ui.Text(c, "分流").FontSize(11).TextColor(t.TextMuted)
				mode := a.cfg.Settings.Routing.Label()
				sel := ui.Select(c, &mode, routingLabelStrings()).Width(104)
				if sel.Changed() {
					a.setRouting(routingFromLabel(mode))
				}
			}
			if firstErr != "" {
				ui.Text(c, firstErr).FontSize(11).TextColor(t.Danger).
					MaxWidth(180).Ellipsis("…").Tooltip(firstErr)
			}
		})
	})
}

// pointsSection 是首屏：顶部上下文栏 + 状态条 + 接入点列表（行间发丝分隔）。
func (a *app) pointsSection(c *ui.Context) {
	t := c.Theme()
	views := a.mgr.Views()
	pageBar(c, "接入点", fmt.Sprintf("%d 个", len(views)), func() {
		if len(views) > 0 {
			if ui.Button(c, "全部登录").Label("全部接入点重新登录").FontSize(11).Clicked() {
				a.mgr.ConnectAll(false)
			}
		}
	})
	ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
		ui.Column(c).Gap(12).Children(func() {
			a.statusBanner(c, views)
			if len(views) == 0 {
				a.emptyState(c)
				return
			}
			// 接入点是一个列表，行间只有发丝线；开关与操作都在行里，不另开弹层。
			panel := ui.Column(c).Radius(12).Background(t.Surface)
			panel.Children(func() {
				for i, v := range views {
					if i > 0 {
						ui.Divider(c)
					}
					a.pointCard(c, v)
				}
			})
			a.recentFailures(c)
		})
	})
}

// recentFailures 把最近几条失败放到首屏卡片下面：首屏下半屏不再空着，
// 需要处理的事一看就能去日志里查。
func (a *app) recentFailures(c *ui.Context) {
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
				a.tab = 2
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

// pointGridBreakpoint 是接入点卡片从三列降为两列的宽度阈值（DIP）。
const pointGridBreakpoint = 980

// pointColumns 让接入点卡片在窄窗口里保持可读：够宽时三列，否则两列。
// 宽度取上一帧的实际可用宽度，首帧直接按三列画。
func (a *app) pointColumns() int {
	if a.pointsWidth > 0 && a.pointsWidth < pointGridBreakpoint {
		return 2
	}
	return 3
}

// noResults 是列表内的「没有结果」提示：留白、字号与层次统一，
// 与整页空状态（emptyState 类的面板）区分开。
func noResults(c *ui.Context, title, hint string) {
	t := c.Theme()
	ui.Column(c).Padding(24).Gap(4).Center().Children(func() {
		ui.Text(c, title).FontSize(13).Bold()
		if hint != "" {
			ui.Text(c, hint).FontSize(11).TextColor(t.TextMuted).
				Wrap().MaxWidth(460)
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
		if ui.PrimaryButton(c, "添加第一个接入点").Clicked() {
			a.openNewEditor()
		}
	})
}

func (a *app) pointCard(c *ui.Context, v vpn.View) {
	t := c.Theme()
	card := ui.Column(c).Key("point:"+v.ID).Padding(16).Gap(8).Radius(14).
		Background(t.Surface).Shadow(0, 2, 10, 0, cardShadow(t))
	card.Children(func() {
		// 三列卡片里可用宽度有限：名称单行省略，地址与说明合成一行。
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Row(c).Size(8, 8).Radius(4).Background(stateColor(t, v.State))
			ui.Column(c).Gap(3).Grow(1).MinWidth(0).Children(func() {
				ui.Text(c, v.Name).FontSize(13).Bold().Ellipsis("…")
				ui.Text(c, addrOf(v)).Font("monospace").FontSize(11).
					TextColor(t.TextMuted).Ellipsis("…")
			})
			a.stateBadge(c, v.State)
		})
		if sub := subtitleOf(v); sub != "" {
			ui.Text(c, sub).FontSize(11).TextColor(t.TextMuted).Ellipsis("…")
		}

		ui.Row(c).GapX(12).GapY(4).Wrap().Children(func() {
			if v.ClientIP != "" {
				meta(c, t, "隧道 IP", v.ClientIP)
			}
			if v.SocksPort > 0 {
				addr := "127.0.0.1:" + strconv.Itoa(v.SocksPort)
				socks := "socks5://" + addr
				metaCopy(c, t, "HTTP / SOCKS5", addr, "复制独立 SOCKS5 地址",
					func() { a.copyText(socks) })
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
			if v.InPool {
				meta(c, t, "统一入口", "参与分流")
			}
		})

		if v.State == vpn.StateError && v.Error != "" {
			ui.Text(c, v.Error).FontSize(13).TextColor(t.Danger)
			if v.Protocol == model.ProtocolEasyConnect && vpn.IsGatewayCertificateError(v.Error) {
				if ui.Button(c, "查看网关证书").Label("查看网关证书 " + v.Name).FontSize(11).Clicked() {
					a.openGatewayCertificate(v.ID)
				}
			}
		}
		// A dead tunnel with a valid login looks "online" everywhere else, so
		// the probe result needs its own line.
		if v.State == vpn.StateOnline {
			for _, probe := range []struct {
				kind   string
				result vpn.ProbeResult
			}{{"DNS", v.DNSProbe}, {"TCP", v.TCPProbe}} {
				colour := t.TextMuted
				if probe.result.State == "failed" {
					colour = t.Warning
				}
				ui.Text(c, healthProbeText(probe.kind, probe.result)).FontSize(11).TextColor(colour).Wrap()
			}
		}
		if v.TunnelState != "" && v.State != vpn.StateError {
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
			ui.Text(c, text).FontSize(13).TextColor(colour).Ellipsis("…")
		}
		summary := vpn.NodeSummary(v)
		showMonitor := v.State == vpn.StateOnline && v.MonitorOn
		// The node summary and the session monitor share one row: the summary
		// on the left, the monitor state and its refresh button on the right.
		if (len(summary) > 0 && v.State == vpn.StateOnline) || showMonitor {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				if len(summary) > 0 && v.State == vpn.StateOnline {
					ui.Text(c, "节点组 "+strings.Join(summary, " · ")).
						FontSize(11).TextColor(t.TextMuted).Grow(1).Ellipsis("…")
				} else {
					ui.Row(c).Grow(1)
				}
				if showMonitor {
					a.sessionMonitor(c, v)
				}
			})
		}
		ui.Row(c).Gap(6).AlignItems(ui.Center).Wrap().Children(func() {
			a.pointButtons(c, v)
		})
	})
}

// sessionMonitor draws the validity state and the manual check button.
func (a *app) sessionMonitor(c *ui.Context, v vpn.View) {
	t := c.Theme()
	colour := t.TextMuted
	switch v.Alive {
	case "有效":
		colour = t.Success
	case "已失效":
		colour = t.Danger
	case "无法确认":
		colour = t.Warning
	}
	state := v.Alive
	if state == "" {
		state = "待检测"
	}
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "会话监测："+state).FontSize(11).TextColor(colour)
		if v.AliveErr != "" && v.Alive != "有效" {
			ui.Text(c, v.AliveErr).FontSize(11).TextColor(t.TextMuted).Ellipsis("…")
		}
		iconButton(c, refreshIcon, "立即检测会话是否仍有效", func() {
			if !a.mgr.CheckNow(v.ID) {
				a.toast = "只有在线的接入点可以检测"
			} else {
				a.toast = "已发起会话有效性检测"
			}
		})
	})
}

func (a *app) pointButtons(c *ui.Context, v vpn.View) {
	switch v.State {
	case vpn.StateOnline:
		if v.Protocol == model.ProtocolEasyConnect && ui.Button(c, "DNS 诊断").Label("DNS 诊断 "+v.Name).FontSize(11).Clicked() {
			a.openDNSProbe(v.ID, v.Name)
		}
		if ui.Button(c, "代理浏览器").Label("代理浏览器 " + v.Name).FontSize(11).Clicked() {
			if err := openProxyBrowser(a.proxyFor(v.ID), "about:blank"); err != nil {
				a.toast = err.Error()
			}
		}
		if ui.Button(c, "断开").Label("断开 " + v.Name).FontSize(11).Clicked() {
			go func() {
				a.localLife.Lock()
				defer a.localLife.Unlock()
				if a.local != nil {
					a.local.StopPoint(v.ID)
				}
				a.mgr.Disconnect(v.ID)
			}()
		}
		// Only the WeCom login keeps a session worth discarding by hand: it is
		// the one where "退出登录" means "sign in as someone else next time".
		if p := a.cfg.Find(v.ID); a.canLogout(p) {
			if ui.Button(c, "退出登录").Label("退出登录 " + v.Name).FontSize(11).Clicked() {
				a.askLogout(v)
			}
		}
	case vpn.StateConnecting:
		if ui.Button(c, "取消").Label("取消 " + v.Name).FontSize(11).Clicked() {
			go a.mgr.Disconnect(v.ID)
		}
	default:
		// One button, and the configured auth mode decides what it does:
		// password logs in by itself, WeCom opens the QR popup, single
		// sign-on needs the browser.
		if ui.PrimaryButton(c, "登录").Label("登录 " + v.Name).FontSize(11).Clicked() {
			a.tunLogf("登录点击：%s（%s）", v.Name, v.ID)
			a.mgr.Connect(v.ID)
		}
	}
	if ui.Button(c, "编辑").Label("编辑 " + v.Name).FontSize(11).Clicked() {
		a.openEditor(v)
	}
}

func (a *app) logPanel(c *ui.Context) {
	t := c.Theme()
	entries := a.bus.Tail(200)
	ui.Column(c).Gap(6).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "运行日志").FontSize(13).Bold()
			ui.Text(c, fmt.Sprintf("最近 %d 条", len(entries))).FontSize(11).
				TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			if ui.Button(c, "复制全部").FontSize(11).Clicked() {
				var b strings.Builder
				for _, e := range entries {
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
						ui.Text(c, e.Line).Font("monospace").FontSize(11).
							TextColor(t.Text).Grow(1).Wrap()
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
	for _, e := range a.bus.Tail(600) {
		if e.Source == vpn.AccessOK || e.Source == vpn.AccessFail {
			entries = append(entries, e)
		}
	}
	pageBar(c, "访问日志", fmt.Sprintf("%d 条", len(entries)), func() {
		// 页面级工具栏用默认字号（13），面板内的动作才用 11。
		if ui.Button(c, "复制全部").Clicked() {
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
		if ui.Button(c, "清空").Clicked() {
			a.bus.Clear()
		}
	})
	ui.Text(c, "本机软件记录 TCP 建立结果；失败条目的路径表示尝试的出口。缺少核心报告时显示「路径未报告」。重复记录合并显示。").FontSize(11).TextColor(t.TextMuted).Wrap()
	scroll := ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4)
	scroll.Children(func() {
		box := ui.Column(c).Padding(10).Radius(12).Border(1, t.Border).
			Background(t.Surface)
		box.Children(func() {
			ui.Column(c).Gap(4).Children(func() {
				if len(entries) == 0 {
					noResults(c, "还没有访问记录",
						"从本机软件页启动项目后，连接会显示在这里；"+
							"支持的核心会报告 VPN 或原出口及命中的规则。")
					return
				}
				for _, e := range entries {
					ok := e.Source == vpn.AccessOK
					ui.Row(c).Gap(8).AlignItems(ui.Start).Children(func() {
						ui.Text(c, e.At.Format("15:04:05")).Font("monospace").
							FontSize(11).TextColor(t.TextMuted)
						dot := t.Danger
						if ok {
							dot = t.Success
						}
						// Center the dot on the first text line, so it lines up
						// with the text instead of hugging the top edge.
						ui.Row(c).Height(15).AlignItems(ui.Center).Children(func() {
							ui.Row(c).Size(8, 8).Radius(4).Background(dot)
						})
						ui.Text(c, e.Line).Font("monospace").FontSize(11).
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
		return "收起日志"
	}
	return "运行日志"
}

// metaCopy draws "key value" with the copy glyph right next to the value: a
// loose row gap left the icon floating far from what it copies.
func metaCopy(c *ui.Context, t *ui.Theme, key, value, tooltip string, onClick func()) {
	ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Text(c, key).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(11).Font("monospace").TextColor(t.Text)
		ui.Row(c).Padding(3).Radius(8).AlignItems(ui.Center).
			OnClick(onClick).Tooltip(tooltip).Children(func() {
			ui.Icon(c, copyIcon).Size(13, 13)
		})
	})
}

func meta(c *ui.Context, t *ui.Theme, key, value string) {
	ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Text(c, key).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(11).Font("monospace").TextColor(t.Text)
	})
}

// stateBadge draws the access point state as a tinted pill: the same hue as
// the status dot, at a tenth of its strength, so it never shouts.
func (a *app) stateBadge(c *ui.Context, state vpn.State) {
	t := c.Theme()
	colour := stateColor(t, state)
	ui.Badge(c, state.Label()).
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
	return model.FormatAccessAddress(v.Server, v.Port)
}

func subtitleOf(v vpn.View) string {
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
	if v.SocksPort > 0 {
		parts = append(parts, "SOCKS5 :"+strconv.Itoa(v.SocksPort))
	} else {
		parts = append(parts, "仅统一入口")
	}
	if v.AutoConnect {
		parts = append(parts, "启动时自动登录")
	}
	return strings.Join(parts, " · ")
}

func displayAddr(addr string) string {
	return strings.Replace(addr, "0.0.0.0", "127.0.0.1", 1)
}

func authModeLabels() []string {
	out := make([]string, 0, len(model.AuthModeLabels))
	for _, entry := range model.AuthModeLabels {
		out = append(out, entry.Label)
	}
	return out
}

func authModeFromLabel(label string) model.AuthMode {
	for _, entry := range model.AuthModeLabels {
		if entry.Label == label {
			return entry.Value
		}
	}
	// The editor no longer offers "自动识别", so an unknown label falls back
	// to the mode that needs the least explanation.
	return model.AuthModePassword
}

func routingLabelStrings() []string {
	out := make([]string, 0, len(model.RoutingLabels))
	for _, entry := range model.RoutingLabels {
		out = append(out, entry.Label)
	}
	return out
}

func routingFromLabel(label string) model.Routing {
	for _, entry := range model.RoutingLabels {
		if entry.Label == label {
			return entry.Value
		}
	}
	return model.RoutingLatency
}

func (a *app) setRouting(r model.Routing) {
	if r == a.cfg.Settings.Routing {
		return
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.Routing = r
		return nil
	}); err != nil {
		a.toast = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		a.toast = "保存设置失败：" + err.Error()
		return
	}
	a.toast = "分流模式已改为「" + r.Label() + "」"
}

// ---- dialogs ----

// 弹窗共用的宽度档位：确认类窄、详情类常规、表单类宽。
const (
	dialogNarrow  float32 = 460
	dialogRegular float32 = 560
	dialogWide    float32 = 640
)

// dialogHeader 是弹窗标题区：标题、可选的副标题，下面一条分隔线。
// 所有弹窗都从这里开始，字号、间距和分隔线才不会各写一套。
func dialogHeader(c *ui.Context, title, subtitle string) {
	t := c.Theme()
	ui.Column(c).Gap(3).Children(func() {
		ui.Text(c, title).FontSize(15).Bold()
		if subtitle != "" {
			ui.Text(c, subtitle).FontSize(11).TextColor(t.TextMuted).Wrap()
		}
	})
	ui.Divider(c)
}

// dialogFooter 是弹窗底部动作区：分隔线 + 一行按钮，左侧留给删除之类的
// 次要动作，右侧放取消与确认。
func dialogFooter(c *ui.Context, fn func()) {
	ui.Divider(c)
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(fn)
}

// 弹窗正文的高度上下限（DIP）：太小看不见内容，太大则把页脚挤出面板。
const (
	dialogBodyMin float32 = 160
	dialogBodyMax float32 = 520
)

// dialogBodyHeight 是弹窗内可滚动区域的高度上限：从窗口高度里扣掉标题、
// 底部按钮、内边距和间距（reserved），这样按钮不会被挤出弹窗。
func (a *app) dialogBodyHeight(reserved float32) float32 {
	h := a.windowH - reserved
	if h < dialogBodyMin {
		h = dialogBodyMin
	}
	if h > dialogBodyMax {
		h = dialogBodyMax
	}
	return h
}

func (a *app) editorView(c *ui.Context) {
	if !a.editor.open {
		return
	}
	t := c.Theme()
	d := &a.editor
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogWide).Gap(10).Children(func() {
			dialogHeader(c, editorTitle(d), editorSubtitle(d))
			ui.Scroll(c).MaxHeight(a.dialogBodyHeight(300)).MinHeight(0).
				ScrollbarInsets(6, 6, 6, 6).Children(func() {
				ui.Column(c).Gap(10).Children(func() {
					ui.Field(c, "VPN 协议", func() { ui.Select(c, &d.protocol, []string{"EasyConnect", "aTrust"}) })
					ui.Field(c, "名称", func() {
						ui.TextInput(c, &d.name).Placeholder("例如：主网关 / 教育网线路")
					})
					// 接入地址先填，检测按钮紧跟着它，点检测时地址已经在上方。
					ui.Field(c, "接入地址", func() {
						ui.TextInput(c, &d.address).
							Placeholder("例如：https://vpn.example.com:443").Grow(1)
					})
					if d.protocol == "EasyConnect" {
						d.authMode, d.authModeLabel = string(model.AuthModePassword), model.AuthModePassword.Label()
						ui.Field(c, "用户名", func() { ui.TextInput(c, &d.username) })
						ui.Field(c, "密码", func() {
							input := ui.TextInput(c, &d.cred).Password()
							if d.hasPassword {
								input.Placeholder("已保存，留空则沿用")
							}
						})
						ui.Text(c, "短信、动态口令或图形验证码会在连接时弹出。无需保存动态口令密钥。").FontSize(11).TextColor(t.TextMuted).Wrap()
						ui.Checkbox(c, &d.advanced, "高级：内网 DNS 与证书兼容")
						if d.advanced {
							ui.Field(c, "VPN DNS（可选，IPv4）", func() { ui.TextInput(c, &d.remoteDNS).Placeholder("留空使用网关下发的 DNS") })
							ui.Field(c, "内网域名后缀（可选，逗号分隔）", func() { ui.TextInput(c, &d.internalDomains).Placeholder("例如：corp.example.com") })
							ui.Field(c, "网关证书 SHA256（可选）", func() {
								ui.TextInput(c, &d.certificateSHA256).Placeholder("可点击下方按钮读取，无需手工查找")
							})
							if ui.Button(c, "读取网关证书…").FontSize(11).Clicked() {
								a.openEditorCertificate()
							}
							ui.Text(c, "读取后展示证书信息，由你确认是否信任；只对当前接入点生效。").FontSize(11).TextColor(t.TextMuted).Wrap()
						}
					} else {
						ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
							ui.Field(c, "认证方式", func() {
								ui.Select(c, &d.authModeLabel, authModeLabels()).Width(220)
								d.authMode = string(authModeFromLabel(d.authModeLabel))
							})
							if ui.Button(c, "检测").FontSize(11).Disabled(d.detecting).Clicked() {
								a.detectEditor()
							}
						})
						if d.detecting {
							ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
								ui.Spinner(c)
								ui.Text(c, "正在读取服务器支持的认证方式…").FontSize(11).TextColor(t.TextMuted)
							})
						}
						if d.detectErr != "" {
							ui.Text(c, d.detectErr).FontSize(11).TextColor(t.Danger)
						}
						if len(d.detected) > 0 {
							ui.Text(c, "服务器支持："+strings.Join(d.detected, "、")).FontSize(11).
								TextColor(t.TextMuted)
						}
						switch d.authMode {
						case string(model.AuthModeWeCom):
							// 企业微信：登录域用来在服务器提供多个外部登录时挑一个。
							ui.Field(c, "登录域（可选）", func() {
								ui.TextInput(c, &d.domain).Placeholder("服务器有多个外部登录方式时用来区分").Width(240)
							})
						case string(model.AuthModeSSO):
							// 单点登录：账号密码在对方页面上完成，这里只说明流程。
							ui.Text(c, "保存后点卡片上的「登录」会打开浏览器完成单点登录，"+
								"登录成功后自动取回会话并连接。").
								FontSize(11).TextColor(t.TextMuted)
						default:
							ui.Field(c, "用户名", func() {
								ui.TextInput(c, &d.username).Placeholder("登录 aTrust 的账号")
							})
							ui.Row(c).Gap(10).AlignItems(ui.End).Children(func() {
								ui.Field(c, "密码", func() {
									in := ui.TextInput(c, &d.cred).Password().Grow(1)
									if d.hasPassword {
										in.Placeholder("已保存，留空则沿用")
									} else {
										in.Placeholder("登录密码")
									}
								})
								ui.Field(c, "登录域", func() {
									ui.TextInput(c, &d.domain).Placeholder("默认 Radius").Width(180)
								})
							})
							ui.Field(c, "TOTP 密钥（可选）", func() {
								ui.TextInput(c, &d.totp).Placeholder("Base32 密钥，留空则不用动态口令")
							})
							if d.hasTOTP {
								ui.Checkbox(c, &d.clearTOTP, "清除已保存的 TOTP 密钥")
							}
						}
					}
					ui.Field(c, "密码存储方式", func() {
						ui.Select(c, &d.secretStore, secretStoreLabels()).Width(220)
						ui.Text(c, "系统凭据服务不可用时仅在本次运行保存，重启后需重新填写。").FontSize(11).TextColor(t.TextMuted).Wrap()
					})
					ui.Divider(c)
					ui.Row(c).Gap(14).AlignItems(ui.Start).Children(func() {
						ui.Field(c, "独立 SOCKS5 端口", func() {
							ui.TextInput(c, &d.socksPort).Width(100)
						})
						// The two boxes follow the field's own rhythm: the first lines
						// up with the "独立 SOCKS5 端口" caption, the second with the
						// input under it.
						ui.Column(c).Gap(9).Children(func() {
							ui.Checkbox(c, &d.inPool, "加入统一入口分流")
							ui.Checkbox(c, &d.autoConnect, "应用启动时自动登录")
						})
					})
					if d.protocol != "EasyConnect" {
						ui.Row(c).Gap(14).AlignItems(ui.Center).Children(func() {
							ui.Checkbox(c, &d.monitor, "监测会话是否仍有效")
							if d.monitor {
								// Label and box on one line: the stacked field wrapped the
								// caption onto two lines and looked out of place here.
								ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
									ui.Text(c, "监测间隔（秒）").FontSize(13)
									ui.TextInput(c, &d.monitorEvery).Width(90)
								})
							}
						})
					}
				})
			})
			if d.err != "" {
				ui.Text(c, d.err).FontSize(11).TextColor(t.Danger)
			}
			// 底部：删除在左，取消与保存在右。
			dialogFooter(c, func() {
				if d.editingID != "" {
					if ui.Button(c, "删除此接入点").FontSize(11).Background(t.Danger).
						TextColor(textOnFill).FontSize(11).
						Label("删除接入点 " + d.name).Clicked() {
						a.deleting = d.editingID
						d.open = false
					}
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "保存").Label("保存接入点").FontSize(11).Clicked() {
					a.saveEditor()
				}
			})
		})
	})
}

func editorSubtitle(d *editorDraft) string {
	if d.editingID == "" {
		return "填好服务器地址与登录方式，保存后回到接入点卡片点「登录」"
	}
	return "改动会在下次登录时生效；需要重新认证的项目请一并更新"
}

func editorTitle(d *editorDraft) string {
	if d.editingID == "" {
		return "添加接入点"
	}
	return "编辑接入点"
}

// 设置页的分区编号：多 tab 共用这一个字段。
const (
	settingGeneral = iota
	settingNetwork
	settingLogs
	settingAbout
)

// settingsPage 是整页设置：顶部多 tab，内容区随分区切换，底部固定保存。
// 原来散在页脚与顶栏的东西——版本、数据目录、运行日志、退出、接管开关——
// 全部收进这里，主界面因此只剩导航与内容。
func (a *app) settingsPage(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	ui.Column(c).Grow(1).MinHeight(0).Gap(10).Children(func() {
		ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
			ui.Text(c, "设置").FontSize(15).Bold()
			ui.Row(c).Grow(1)
			if ui.Button(c, "返回").Label("关闭设置").FontSize(11).Clicked() {
				d.open = false
			}
		})
		ui.Segmented(c, &d.section, "通用", "网络与接管", "日志", "关于").Label("设置分类")
		ui.Divider(c)
		ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
			ui.Column(c).Gap(12).Children(func() {
				switch d.section {
				case settingNetwork:
					a.captureSection(c)
				case settingLogs:
					a.logsSection(c)
				case settingAbout:
					a.aboutSection(c)
				default:
					a.generalSection(c)
				}
			})
		})
		if d.err != "" {
			ui.Text(c, d.err).FontSize(11).TextColor(t.Danger)
		}
		ui.Divider(c)
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "改动即时生效，不需要保存").FontSize(11).TextColor(t.TextMuted)
			ui.Row(c).Grow(1)
			if ui.Button(c, "完成").Label("关闭设置").FontSize(11).Clicked() {
				d.open = false
			}
		})
	})
}

// generalSection 是原来的设置弹窗内容，按整页排版重新分好组。
func (a *app) generalSection(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	ui.Field(c, "监听地址", func() {
		e := ui.TextInput(c, &d.host).Placeholder("127.0.0.1").Width(180)
		// 文本项在回车或失焦时落盘，免得每敲一个字就写一次配置。
		if e.Submitted() || e.PressedOutside() {
			a.applySettingsIfChanged()
		}
	})
	ui.Row(c).Gap(12).AlignItems(ui.End).Children(func() {
		ui.Field(c, "统一入口端口", func() {
			e := ui.TextInput(c, &d.port).Width(110)
			if e.Submitted() || e.PressedOutside() {
				a.applySettingsIfChanged()
			}
		})
		ui.Field(c, "健康检查间隔（秒）", func() {
			e := ui.TextInput(c, &d.interval).Width(110)
			if e.Submitted() || e.PressedOutside() {
				a.applySettingsIfChanged()
			}
		})
	})
	ui.Field(c, "分流模式", func() {
		if ui.Select(c, &d.routing, routingLabelStrings()).Width(160).Changed() {
			a.applySettingsIfChanged()
		}
	})
	ui.Field(c, "颜色模式", func() {
		if ui.Select(c, &d.appearance, appearanceLabels()).Width(160).Changed() {
			a.applySettingsIfChanged()
		}
	})
	a.themeCards(c)
	ui.Text(c, "跟随系统时，窗口外观跟着操作系统的深浅设置变；浅色与深色会把外观固定下来。").
		FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(560)
	ui.Column(c).Gap(4).Children(func() {
		if ui.Checkbox(c, &d.aggregate, "开启统一入口 SOCKS5").Changed() {
			a.applySettingsIfChanged()
		}
		if ui.Checkbox(c, &d.autoReconnect, "连接断开时自动重连").Changed() {
			a.applySettingsIfChanged()
		}
		if supportsDockToggle() {
			if ui.Checkbox(c, &d.hideDock, "关闭后隐藏 Dock 图标").Changed() {
				a.applySettingsIfChanged()
			}
		}
	})
	ui.Text(c, "监听 127.0.0.1 只有本机能用；要让局域网里的设备用，"+
		"改成 0.0.0.0，但 SOCKS5 没有认证，请只在自己信任的网络里这样做。").
		FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(560)
}

// captureSection 是「网络与接管」：接管方式是一个下拉，状态与诊断在下面。
func (a *app) captureSection(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	// 下拉反映真实状态；用户改选时由 applyCaptureMode 负责先关掉其他方式。
	d.mode = a.captureMode()
	ui.Field(c, "接管方式", func() {
		sel := ui.Select(c, &d.mode, captureModes()).Width(180)
		if sel.Changed() {
			a.applyCaptureMode(d.mode)
		}
	})
	agg := a.mgr.Aggregate()
	ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
		ui.Text(c, "当前接管："+a.captureMode()).FontSize(11).TextColor(t.TextMuted)
		ui.Row(c).Grow(1)
		if agg.Running {
			addr := "socks5://" + displayAddr(agg.Addr)
			ui.Text(c, addr).Font("monospace").FontSize(11).TextColor(t.TextMuted)
			if ui.Button(c, "复制入口").Label("复制统一入口地址").FontSize(11).Clicked() {
				a.copyText(addr)
			}
		} else {
			ui.Text(c, "统一入口未监听").FontSize(11).TextColor(t.TextMuted)
		}
	})
	ui.Text(c, "系统代理只改浏览器等应用的代理设置；全局 TUN 接管整机 IPv4 TCP；"+
		"应用接管只针对选中的应用。三者互斥，同一时间只能开一个。").
		FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(620)
	ui.Divider(c)
	a.captureStatus(c)
}

// logsSection 是「日志」：运行日志开关与访问日志页入口。
func (a *app) logsSection(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Text(c, "运行日志").FontSize(13).Bold()
		ui.Row(c).Grow(1)
		if ui.Button(c, logLabel(a.logsOpen)).FontSize(11).Clicked() {
			a.logsOpen = !a.logsOpen
		}
		if ui.Button(c, "访问日志页").FontSize(11).Clicked() {
			a.settings.open = false
			a.tab = 2
		}
	})
	if a.logsOpen {
		a.logPanel(c)
	} else {
		ui.Text(c, "运行日志记录登录、断开、接管与连接失败；打开后可复制或清空。").
			FontSize(11).TextColor(t.TextMuted)
	}
	ui.Divider(c)
	ui.Text(c, "TUN 与接管日志").FontSize(13).Bold()
	ui.Text(c, "系统 TUN 与应用接管的详细日志单独存放，排查接管问题时先看这里。").
		FontSize(11).TextColor(t.TextMuted)
	if ui.Button(c, "打开 TUN 日志").FontSize(11).Clicked() {
		a.openTUNLog()
	}
}

// aboutSection 是「关于」：版本、更新、项目主页、数据目录与退出。
func (a *app) aboutSection(c *ui.Context) {
	t := c.Theme()
	ui.Field(c, "版本", func() { ui.Text(c, appName+" "+appBuild).FontSize(13) })
	ui.Row(c).Gap(8).Wrap().Children(func() {
		if ui.Button(c, "项目主页").FontSize(11).Clicked() {
			a.openProject()
		}
		if ui.Button(c, "打开数据目录").FontSize(11).Clicked() {
			if err := mygo.Shell.OpenPath(a.dir); err != nil {
				a.toast = "打不开数据目录：" + err.Error()
			}
		}
		if a.update != nil {
			if ui.PrimaryButton(c, "下载 v"+a.update.Version).FontSize(11).Clicked() {
				a.openUpdate()
			}
		}
	})
	ui.Divider(c)
	ui.Text(c, "退出会断开所有隧道；正在接管时请先关闭接管再退出。").FontSize(11).TextColor(t.TextMuted)
	if ui.Button(c, "退出 "+appName).FontSize(11).Background(t.Danger).TextColor(textOnFill).Clicked() {
		a.askQuit()
	}
}

func (a *app) deleteView(c *ui.Context) {
	if a.deleting == "" {
		return
	}
	t := c.Theme()
	var p *model.AccessPoint
	for i := range a.cfg.Points {
		if a.cfg.Points[i].ID == a.deleting {
			p = &a.cfg.Points[i]
			break
		}
	}
	open := a.deleting != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "删除接入点", "只影响这个接入点，其他配置不变")
			name := "这个接入点"
			if p != nil {
				name = "「" + p.Name + "」"
			}
			ui.Text(c, "删除 "+name+" 会断开它的登录，并删除保存的密码和 TOTP 密钥。").
				FontSize(13).TextColor(t.Text)
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.deleting = ""
				}
				if ui.PrimaryButton(c, "确认删除").FontSize(11).Clicked() {
					a.removePoint(a.deleting)
					a.deleting = ""
				}
			})
		})
	})
	if !open {
		a.deleting = ""
	}
}

// canLogout reports whether "退出登录" is offered for a point: only a login
// that came from an external page leaves a session worth discarding by hand.
// That is the WeCom QR login, single sign-on, and the legacy "auto" mode —
// which, without a stored password, is the WeCom login too. A point that logs
// in with a password has nothing to discard, so it shows no such button.
func (a *app) canLogout(p *model.AccessPoint) bool {
	if p == nil {
		return false
	}
	switch model.AuthMode(p.AuthMode) {
	case model.AuthModeWeCom, model.AuthModeSSO:
		return true
	case model.AuthModeAuto:
		// 老配置的 auto：有密码就走密码，没有密码才落到企业微信。
		_, err := a.store.Password(p.ID)
		return errors.Is(err, store.ErrSecretNotFound)
	}
	return false
}

// askLogout refuses while the global TUN owns the session, then opens the
// confirmation: forgetting the authentication forces a new QR scan.
func (a *app) askLogout(v vpn.View) {
	if a.tunOn {
		for _, id := range splitIDs(a.tunPoints) {
			if id == v.ID {
				a.toast = "这个接入点正被全局 TUN 使用，先关闭 TUN 再退出登录"
				return
			}
		}
	}
	a.win.Update(func() { a.logoutAsk = v.ID })
}

// logoutView confirms forgetting a point's saved login.
func (a *app) logoutView(c *ui.Context) {
	if a.logoutAsk == "" {
		return
	}
	t := c.Theme()
	name := "这个接入点"
	var point *model.AccessPoint
	for i := range a.cfg.Points {
		if a.cfg.Points[i].ID == a.logoutAsk {
			name = "「" + a.cfg.Points[i].Name + "」"
			point = &a.cfg.Points[i]
		}
	}
	// 只有单点登录的会话存在浏览器里，才需要连浏览器数据一起清掉。
	usesBrowser := point != nil && model.AuthMode(point.AuthMode) == model.AuthModeSSO
	body := "退出 " + name + " 会清除本地暂存的认证信息，下次登录需要重新认证。"
	hint := "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，" +
		"那样下次登录会直接复用这次认证，不用重新扫码。"
	if usesBrowser {
		body = "退出 " + name + " 会清除本地暂存的认证信息与浏览器登录数据（cookie），下次登录需要重新认证。"
		hint = "如果只是想暂时断开、稍后继续用同一个账号，点「断开」即可，" +
			"那样下次登录会直接复用这次认证，不会重新打开浏览器认证。"
	}
	open := a.logoutAsk != ""
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "退出登录", body)
			ui.Text(c, hint).FontSize(11).TextColor(t.TextMuted).Wrap()
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.logoutAsk = ""
				}
				if ui.Button(c, "确认退出登录").FontSize(11).Background(t.Danger).
					TextColor(textOnFill).Clicked() {
					id := a.logoutAsk
					a.logoutAsk = ""
					go func() {
						a.mgr.Logout(id)
						// 企业微信的认证不在浏览器里，清配置目录反而会丢掉
						// 有用的东西；只有单点登录需要连浏览器会话一起清。
						if p := a.cfg.Find(id); p != nil && logoutClearsBrowser(model.AuthMode(p.AuthMode)) {
							a.clearBrowserLoginProfile(id)
						}
					}()
					a.toast = "已退出登录，下次登录需要重新认证"
				}
			})
		})
	})
	if !open {
		a.logoutAsk = ""
	}
}

// quitView asks before closing the app: quitting drops every tunnel and, with
// the global TUN on, restores the system DNS.
func (a *app) quitView(c *ui.Context) {
	if !a.quitAsk {
		return
	}
	t := c.Theme()
	open := a.quitAsk
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "退出 "+appName, "退出前先确认这几件事")
			online, _, _ := a.mgr.Counts()
			line := "退出会断开所有隧道。"
			if a.tunOn {
				line += "全局 TUN 会关闭，系统 DNS 与代理恢复原状。"
			}
			if online > 0 {
				line += fmt.Sprintf("当前有 %d 个接入点在线。", online)
			}
			ui.Text(c, line).FontSize(13).TextColor(t.Text).Wrap()
			ui.Text(c, "退出后数据库转发和软件接管会停止。软件窗口保留；停止接管的软件新连接恢复系统网络。").
				FontSize(11).TextColor(t.TextMuted).Wrap()
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.quitAsk = false
				}
				if ui.Button(c, "确认退出").FontSize(11).Background(t.Danger).
					TextColor(textOnFill).Clicked() {
					a.quitAsk = false
					a.doQuit()
				}
			})
		})
	})
	if !open {
		a.quitAsk = false
	}
}

// ---- actions ----

func (a *app) openNewEditor() {
	a.editor = editorDraft{
		certificateToken: model.NewID(),
		protocol:         "EasyConnect",
		open:             true,
		address:          "",
		authMode:         string(model.AuthModePassword),
		authModeLabel:    model.AuthModePassword.Label(),
		socksPort:        strconv.Itoa(a.cfg.NextSocksPort()),
		inPool:           true,
		autoConnect:      false,
		monitor:          true,
		monitorEvery:     "300",
		secretStore:      secretStoreLabel(a.cfg.Settings.SecretStore),
	}
}

func (a *app) openEditor(v vpn.View) {
	p := a.cfg.Find(v.ID)
	if p == nil {
		return
	}
	mode := model.AuthMode(p.AuthMode)
	if mode == model.AuthModeAuto {
		// "自动识别" is gone from the editor: show what the old point has
		// actually been doing, so saving turns it into an explicit mode.
		if a.hasPassword(p.ID) {
			mode = model.AuthModePassword
		} else {
			mode = model.AuthModeWeCom
		}
	}
	a.editor = editorDraft{
		certificateToken:       model.NewID(),
		certificateAddress:     net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
		certificateAcceptedPin: p.CertificateSHA256,
		open:                   true,
		editingID:              p.ID,
		protocol:               protocolLabel(p.Protocol),
		remoteDNS:              p.RemoteDNS,
		internalDomains:        strings.Join(p.InternalDomains, ", "),
		certificateSHA256:      p.CertificateSHA256,
		name:                   p.Name,
		address:                model.FormatAccessAddress(p.Server, p.Port),
		username:               p.Username,
		authMode:               string(mode),
		authModeLabel:          mode.Label(),
		domain:                 p.LoginDomain,
		socksPort:              strconv.Itoa(p.SocksPort),
		inPool:                 p.InPool,
		autoConnect:            p.AutoConnect,
		monitor:                p.MonitorEnabled(),
		monitorEvery:           strconv.Itoa(p.MonitorIntervalSeconds()),
		secretStore:            secretStoreLabel(a.cfg.Settings.SecretStore),
		hasPassword:            a.hasPassword(p.ID),
		detected:               nil,
	}
	a.editor.hasTOTP = a.hasTOTP(p.ID)
	// A point saved before the mode was a choice gets the mode the server
	// actually offers, picked by detection instead of a "detect yourself"
	// dropdown entry.
	if strings.TrimSpace(p.AuthMode) == "" || model.AuthMode(p.AuthMode) == model.AuthModeAuto {
		a.editor.autoPick = true
	}
	if a.editor.autoPick {
		a.detectEditor()
	}
}

func (a *app) saveEditor() {
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.err = err.Error()
		return
	}
	socksPort, err := parseOptionalPort(d.socksPort)
	if err != nil {
		d.err = "独立 SOCKS5 端口：" + err.Error()
		return
	}
	if strings.TrimSpace(server) == "" {
		d.err = "服务器地址不能为空"
		return
	}
	if err := d.checkCertificateAddress(server, port); err != nil {
		d.err = err.Error()
		return
	}
	mode := string(authModeFromLabel(d.authModeLabel))
	if mode == "" {
		mode = d.authMode
	}
	switch model.AuthMode(mode) {
	case model.AuthModeWeCom, model.AuthModeSSO:
		// Neither needs a username or a stored password: WeCom shows a QR
		// code, single sign-on runs on the portal's own page.
	case model.AuthModeAuto:
		if strings.TrimSpace(d.cred) != "" && strings.TrimSpace(d.username) == "" {
			d.err = "填了密码就要填用户名"
			return
		}
	default:
		if strings.TrimSpace(d.username) == "" {
			d.err = "用户名不能为空"
			return
		}
		if strings.TrimSpace(d.cred) == "" && !d.hasPassword {
			d.err = "请填写密码"
			return
		}
	}
	if !d.inPool && socksPort == 0 {
		d.err = "至少勾选统一入口，或填一个独立 SOCKS5 端口"
		return
	}
	// Switching away from the password mode leaves no one to use a
	// username: drop it so the card does not show an account that is never
	// sent.
	username := strings.TrimSpace(d.username)
	if model.AuthMode(mode) != model.AuthModePassword && model.AuthMode(mode) != model.AuthModeAuto {
		username = ""
	}
	p := model.AccessPoint{
		Protocol:          protocolFromLabel(d.protocol),
		RemoteDNS:         d.remoteDNS,
		InternalDomains:   strings.FieldsFunc(d.internalDomains, func(r rune) bool { return r == ',' || r == '，' || r == '\n' }),
		CertificateSHA256: d.certificateSHA256,
		ID:                d.editingID,
		Name:              strings.TrimSpace(d.name),
		Server:            server,
		Port:              port,
		Username:          username,
		AuthMode:          mode,
		LoginDomain:       strings.TrimSpace(d.domain),
		SocksPort:         socksPort,
		InPool:            d.inPool,
		AutoConnect:       d.autoConnect,
	}
	monitor := d.monitor
	p.Monitor = &monitor
	if every, err := strconv.Atoi(strings.TrimSpace(d.monitorEvery)); err == nil && every > 0 {
		p.MonitorInterval = every
	} else {
		p.MonitorInterval = 300
	}
	p.Normalize()
	if p.ID == "" {
		p.ID = model.NewID()
	}
	if err := p.Validate(); err != nil {
		d.err = err.Error()
		return
	}
	if socksPort == a.cfg.Settings.AggregatePort {
		d.err = "独立 SOCKS5 端口不能和统一入口端口相同"
		return
	}

	// Secrets first, so that a point is never saved without the creds it
	// needs when the user typed new ones.
	if strings.TrimSpace(d.cred) != "" {
		if err := a.store.SetPassword(p.ID, d.cred); err != nil {
			d.err = "保存密码失败：" + err.Error()
			return
		}
	}
	if d.clearTOTP {
		if err := a.store.SetTOTP(p.ID, ""); err != nil {
			d.err = "清除 TOTP 失败：" + err.Error()
			return
		}
	} else if strings.TrimSpace(d.totp) != "" {
		if err := a.store.SetTOTP(p.ID, strings.TrimSpace(d.totp)); err != nil {
			d.err = "保存 TOTP 失败：" + err.Error()
			return
		}
	}

	_, err = a.store.Update(func(cfg *model.Config) error {
		for _, other := range cfg.Points {
			if other.ID != p.ID && socksPort > 0 && other.SocksPort == socksPort {
				return fmt.Errorf("SOCKS5 端口 %d 已被「%s」使用", socksPort, other.Name)
			}
		}
		if d.editingID == "" {
			added := cfg.Add(p)
			// Add assigns a free port for callers that do not care; the
			// editor's explicit 0 means "no per-point proxy".
			added.SocksPort = socksPort
			p.ID = added.ID
			return nil
		}
		_, err := cfg.Update(p)
		return err
	})
	if err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	// The password store is a global setting, chosen here for convenience.
	if newStore := secretStoreFromLabel(d.secretStore); newStore != a.cfg.Settings.SecretStore {
		if _, err := a.store.Update(func(cfg *model.Config) error {
			cfg.Settings.SecretStore = newStore
			return nil
		}); err != nil {
			d.err = "保存密码存储方式失败：" + err.Error()
			return
		}
		if err := a.saveConfig(); err != nil {
			d.err = "保存密码存储方式失败：" + err.Error()
			return
		}
		a.toast = "已保存「" + p.Name + "」，密码存储方式改为「" + d.secretStore + "」，重启后生效"
		d.open = false
		return
	}
	d.open = false
	a.toast = "已保存「" + p.Name + "」"
}

// detectEditor asks the server which login methods it offers, for the
// editor's "detect" button. It runs beside the view and updates the draft
// on the main thread.
func (a *app) detectEditor() {
	if a.editor.protocol == "EasyConnect" {
		return
	}
	d := &a.editor
	server, port, err := model.ParseAccessAddress(d.address)
	if err != nil {
		d.detectErr = err.Error()
		d.detected = nil
		return
	}
	d.detecting = true
	d.detectErr = ""
	d.detected = nil
	d.detectGen++
	gen := d.detectGen
	domain := d.domain
	mode := d.authMode
	a.invalidate()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		methods, err := vpn.DetectAuthMethods(ctx, model.AccessPoint{
			Server: server, Port: port, LoginDomain: domain,
		})
		update := func() {
			if d.detectGen != gen || !d.open {
				return
			}
			d.detecting = false
			if err != nil {
				d.detectErr = "检测失败：" + err.Error()
				return
			}
			labels := make([]string, 0, len(methods))
			hasExternal, hasPassword := false, false
			for _, m := range methods {
				labels = append(labels, m.Label())
				switch m.Type {
				case "auth/qywechat", "auth/httpsOauth2", "auth/cas":
					hasExternal = true
				case "auth/psw":
					hasPassword = true
				}
			}
			d.detected = labels
			if len(labels) == 0 {
				d.detectErr = "服务器没有返回可用的认证方式"
				return
			}
			if d.autoPick {
				// 企业微信优先（有扫码就用扫码），其次是单点登录，
				// 最后才是账号密码：这正是服务器给出的顺序所意味的。
				picked := model.AuthModePassword
				switch {
				case hasWeCom(methods):
					picked = model.AuthModeWeCom
				case hasSSO(methods):
					picked = model.AuthModeSSO
				}
				d.authMode = string(picked)
				d.authModeLabel = picked.Label()
				d.autoPick = false
			}
			// 账号密码模式下，服务器只提供密码登录而表单还没填密码时，
			// 直接把下一步说清楚，省得保存后才报错。
			if mode == string(model.AuthModePassword) && !hasExternal && hasPassword && !d.hasPassword && strings.TrimSpace(d.cred) == "" {
				d.detectErr = "服务器只支持账号密码，请填写用户名和密码"
			}
		}
		if a.win != nil {
			a.win.Update(update)
		} else {
			update()
		}
	}()
}

// toggleSystemProxy points the macOS system proxy at the unified entry, or
// clears it, so browsers need no manual proxy setup.
// firstOnlinePoint returns the ID of the first online access point.
func (a *app) openTUNLog() {
	path := filepath.Join(a.dir, "tun.log")
	if _, err := os.Stat(path); err != nil {
		a.toast = "尚无 TUN 日志；代理请求请查看访问日志"
		return
	}
	if err := mygo.Shell.OpenPath(path); err != nil {
		a.toast = "打开日志失败：" + err.Error()
	}
}

func (a *app) firstOnlinePoint() string {
	for _, v := range a.mgr.Views() {
		if v.State == vpn.StateOnline {
			return v.ID
		}
	}
	return ""
}

func (a *app) toggleSystemProxy() {
	if a.resourceTUNActive() {
		a.toast = "请先关闭系统 TUN 再切换系统代理"
		return
	}
	if a.releaseLostSystemProxy() {
		a.toast = "系统代理已由其他软件修改，已更新开关状态并保留当前配置"
		return
	}
	if a.tunOn && !a.sysProxyOn {
		a.toast = "全局 TUN 已经接管流量，先关掉 TUN 再用系统代理"
		a.sysProxySwitch = a.sysProxyOn
		return
	}
	agg := a.mgr.Aggregate()
	if !agg.Running || agg.Addr == "" {
		a.toast = "统一入口还没启动"
		a.sysProxySwitch = a.sysProxyOn
		return
	}
	// 先确认代理端口真的在监听：指到一个没人听的端口会让整台机器断网。
	if conn, err := net.DialTimeout("tcp", agg.Addr, 2*time.Second); err != nil {
		a.toast = "统一入口没有在监听，先别开系统代理"
		a.sysProxySwitch = a.sysProxyOn
		return
	} else {
		_ = conn.Close()
	}
	port := agg.Addr
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i+1:]
	}
	target := "127.0.0.1:" + port
	on := !a.sysProxyOn
	a.toast = "正在修改系统代理，请授权…"
	a.invalidate()
	go func() {
		err := applySystemProxyFn(target, on)
		a.win.Update(func() {
			if err != nil {
				a.toast = "系统代理设置失败：" + err.Error()
				return
			}
			a.sysProxyOn = on
			if on {
				a.toast = "已把系统代理设为 " + target
			} else {
				a.toast = "已取消系统代理"
			}
		})
	}()
}

func (a *app) openSettings() {
	s := a.cfg.Settings
	a.settings = settingsDraft{
		open:          true,
		section:       a.settings.section,
		appearance:    appearanceLabel(a.savedAppearance()),
		theme:         a.savedTheme(),
		host:          s.ListenHost,
		port:          strconv.Itoa(s.AggregatePort),
		interval:      strconv.Itoa(s.HealthIntervalSec),
		routing:       s.Routing.Label(),
		aggregate:     s.AggregateEnabled,
		autoReconnect: s.AutoReconnect,
		secretStore:   secretStoreLabel(s.SecretStore),
		hideDock:      s.HideDock,
	}
}

// openSettingsAt 从顶栏直接进入指定分区：齿轮进上次所在分区，网络状态进网络分区。
func (a *app) openSettingsAt(section int) {
	a.openSettings()
	a.settings.section = section
	a.invalidate()
}

func (a *app) saveSettings() {
	d := &a.settings
	port, err := parsePort(d.port, "统一入口端口")
	if err != nil {
		d.err = err.Error()
		return
	}
	interval, err := strconv.Atoi(strings.TrimSpace(d.interval))
	if err != nil || interval < 0 {
		d.err = "健康检查间隔必须是不小于 0 的整数"
		return
	}
	host := strings.TrimSpace(d.host)
	if host == "" {
		d.err = "监听地址不能为空"
		return
	}
	for _, p := range a.cfg.Points {
		if p.SocksPort == port {
			d.err = fmt.Sprintf("端口 %d 已被「%s」的独立代理使用", port, p.Name)
			return
		}
	}
	_, err = a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.ListenHost = host
		cfg.Settings.AggregatePort = port
		cfg.Settings.HealthIntervalSec = interval
		cfg.Settings.Routing = routingFromLabel(d.routing)
		cfg.Settings.AggregateEnabled = d.aggregate
		cfg.Settings.AutoReconnect = d.autoReconnect
		cfg.Settings.HideDock = d.hideDock
		cfg.Settings.Appearance = appearanceFromLabel(d.appearance)
		cfg.Settings.Theme = d.theme
		cfg.Settings.SecretStore = secretStoreFromLabel(d.secretStore)
		return cfg.Settings.Validate()
	})
	if err != nil {
		d.err = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		d.err = "保存配置失败：" + err.Error()
		return
	}
	// 实时生效：不关页、不弹提示，输入框里能马上看到结果。
	d.err = ""
}

// applySettingsIfChanged 是「改动即时落盘」的入口：只有草稿真的与
// 已保存的值不同才写一次，避免每帧都碰磁盘。
func (a *app) applySettingsIfChanged() {
	if !a.settingsDirty() {
		return
	}
	a.saveSettings()
}

// settingsDirty 拿草稿和已保存的设置逐项比。
func (a *app) settingsDirty() bool {
	d := &a.settings
	s := a.cfg.Settings
	return strings.TrimSpace(d.host) != s.ListenHost ||
		strings.TrimSpace(d.port) != strconv.Itoa(s.AggregatePort) ||
		strings.TrimSpace(d.interval) != strconv.Itoa(s.HealthIntervalSec) ||
		appearanceFromLabel(d.appearance) != a.savedAppearance() ||
		d.theme != a.savedTheme() ||
		routingFromLabel(d.routing) != s.Routing ||
		d.aggregate != s.AggregateEnabled ||
		d.autoReconnect != s.AutoReconnect ||
		d.hideDock != s.HideDock ||
		secretStoreFromLabel(d.secretStore) != s.SecretStore
}

func (a *app) removePoint(id string) {
	for _, p := range a.cfg.LocalApps {
		if p.PointID == id {
			a.toast = "「" + p.Name + "」仍使用此接入点，请先在本机软件中更换或删除"
			return
		}
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Remove(id)
		return nil
	}); err != nil {
		a.toast = err.Error()
		return
	}
	if err := a.saveConfig(); err != nil {
		a.toast = "保存配置失败：" + err.Error()
		return
	}
	_ = a.store.DeleteSecrets(id)
	a.toast = "已删除接入点"
}

func parsePort(s, what string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s必须是 1–65535 的整数", what)
	}
	return port, nil
}

func parseOptionalPort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(s)
	if err != nil || port < 0 || port > 65535 {
		return 0, fmt.Errorf("必须是 0–65535 的整数")
	}
	return port, nil
}

func secretStoreLabels() []string {
	return []string{"系统钥匙串", "本地文件（明文）"}
}

func secretStoreLabel(v string) string {
	if v == model.SecretStoreKeychain {
		return "系统钥匙串"
	}
	return "本地文件（明文）"
}

func secretStoreFromLabel(label string) string {
	if label == "系统钥匙串" {
		return model.SecretStoreKeychain
	}
	return model.SecretStoreFile
}

// hasWeCom reports whether the server offers the WeCom QR login, which the
// app completes in its own popup.
func hasWeCom(methods []vpn.AuthMethod) bool {
	for _, m := range methods {
		if m.Type == "auth/qywechat" {
			return true
		}
	}
	return false
}

// hasSSO reports whether the server offers a single sign-on that only finishes
// in a real browser.
func hasSSO(methods []vpn.AuthMethod) bool {
	for _, m := range methods {
		switch m.Type {
		case "auth/cas", "auth/httpsOauth2":
			return true
		}
	}
	return false
}

// hostInTun reports whether a point is one the running helper serves. The
// snapshot is a comma-joined list of point IDs.
func hostInTun(points, id string) bool {
	for _, p := range strings.Split(points, ",") {
		if strings.TrimSpace(p) == id {
			return true
		}
	}
	return false
}

// appFilterValue maps the segmented control's choice to the filter used by the
// list: 0 所有, 1 已启用, 2 未启用.
func appFilterValue(index int) string {
	switch index {
	case 1:
		return "on"
	case 2:
		return "off"
	default:
		return "all"
	}
}

// logoutClearsBrowser reports whether discarding a login must also wipe the
// browser data. Only single sign-on keeps its session in a browser; the WeCom
// login lives in the app's own window and its files are not worth touching.
func logoutClearsBrowser(mode model.AuthMode) bool {
	return mode == model.AuthModeSSO
}

func protocolLabel(value string) string {
	if value == model.ProtocolEasyConnect {
		return "EasyConnect"
	}
	return "aTrust"
}
func protocolFromLabel(label string) string {
	if label == "EasyConnect" {
		return model.ProtocolEasyConnect
	}
	return model.ProtocolATrust
}
