package main

// 简单模式：一个接入点、一个网址输入框，其余概念收进设置页。
//
// 它是「展示层裁剪 + 默认值收敛」，不复制任何业务逻辑：接管方式仍然走
// captureModes/applyCaptureMode，登录、断开、代理浏览器全都复用现有实现。
// 唯一新增的写入口是 setSimpleMode，它负责落盘、收敛和把 tab 收回到存在的页面。

import (
	"fmt"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// siteTileLimit 限制磁贴数量：单接入点用户要的是「最近在用的几个」，
// 不是把网关上下发的几十个应用铺满首屏。
const siteTileLimit = 8

// simpleMode 报告界面是否处于简单模式。
func (a *app) simpleMode() bool { return a.cfg.Settings.SimpleMode }

// setSimpleMode 开关简单模式。它是唯一写入口（设置页的开关与「显示全部设置」
// 都走这里）：落盘、收敛默认值、把 tab 收回到当前模式下存在的页面上。
func (a *app) setSimpleMode(on bool) {
	if a.store == nil {
		a.cfg.Settings.SimpleMode = on
		if on {
			a.cfg.ConvergeSimple()
		}
		a.settings.simpleMode = on
		a.settings.aggregate = a.cfg.Settings.AggregateEnabled
		a.clampTab()
		return
	}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.SimpleMode = on
		if on {
			// 只收敛「参与统一入口」与「开启统一入口」。改每点端口会让 Manager
			// 重建在线的隧道（见 ConvergeSimple 的注释），退出时也不用还原。
			cfg.ConvergeSimple()
		}
		return nil
	}); err != nil {
		a.settings.simpleMode = a.simpleMode()
		a.setToast("切换简单模式失败：" + err.Error())
		return
	}
	if err := a.saveConfig(); err != nil {
		a.settings.simpleMode = a.simpleMode()
		a.setToast("保存简单模式失败：" + err.Error())
		return
	}
	// 收敛只动了 AggregateEnabled：同步草稿里这一项，别让 dirty 比对跟它顶牛。
	// 其余草稿保持原样——整份重读会把用户刚看到的校验错误抹掉。
	a.settings.simpleMode = on
	a.settings.aggregate = a.cfg.Settings.AggregateEnabled
	a.clampTab()
	a.invalidate()
}

// siteTile 是「内网网站」里的一张磁贴：一个名字加一个能直接用代理浏览器打开的地址。
type siteTile struct {
	Name string
	URL  string
}

// siteTarget 把输入框里的东西规整成一个地址：空的不开，缺协议的补 https。
func siteTarget(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return s, true
}

// simpleSiteTiles 汇总这个接入点下能直接打开的地址：网关下发的应用在前，
// 本机保存的浏览器项目在后，按地址去重。离线时只用本机保存的那些——
// 没登录就让人点进一个必然打不开的地址是很糟的体验。
func (a *app) simpleSiteTiles(v vpn.View) []siteTile {
	seen := make(map[string]bool, siteTileLimit)
	tiles := make([]siteTile, 0, siteTileLimit)
	add := func(name, url string) {
		url = strings.TrimSpace(url)
		if url == "" || seen[url] || len(tiles) >= siteTileLimit {
			return
		}
		seen[url] = true
		tiles = append(tiles, siteTile{Name: name, URL: url})
	}
	if v.State == vpn.StateOnline {
		for _, app := range v.Apps {
			add(app.Name, appOpenURL(app))
		}
	}
	for _, p := range a.cfg.LocalApps {
		if p.PointID != v.ID || p.Mode != model.LocalAppBrowser {
			continue
		}
		add(p.Name, p.URL)
	}
	return tiles
}

// openSiteInProxyBrowser 用这个接入点的代理打开地址。简单模式下 proxyFor 一律
// 回统一入口（每点端口被忽略），所以用户只需要知道一个地址。
func (a *app) openSiteInProxyBrowser(v vpn.View, url string) {
	proxy := a.proxyFor(v.ID)
	if proxy == "" {
		a.setToast("还没有可用的代理：先登录这个接入点")
		return
	}
	if err := openProxyBrowser(proxy, url); err != nil {
		a.setToast("没能启动浏览器：" + err.Error() + "；代理是 " + proxy)
	}
}

// simpleHome 是简单模式的首屏：一张状态卡、接管方式、网址入口。
// 只有恰好一个接入点时用它；多个点退回列表，单卡描述不了复数。
func (a *app) simpleHome(c *ui.Context, v vpn.View) {
	ui.Column(c).Grow(1).MinHeight(0).Gap(12).Children(func() {
		pageBar(c, "连接", "1 个接入点", func() {
			if ui.Button(c, "高级设置").FontSize(11).Clicked() {
				a.openSettingsAt(settingGeneral)
			}
		})
		ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
			ui.Column(c).Gap(12).Children(func() {
				a.simpleHero(c, v)
				a.simpleSites(c, v)
				// 护栏：失败在首屏就能看到，日志入口跟着模式走。
				a.recentFailures(c)
			})
		})
	})
}

// simpleEmpty 是简单模式下还没有接入点时的首屏：一句引导加一个添加按钮，
// 不摆常用入口和状态条——它们此刻什么也说明不了。
func (a *app) simpleEmpty(c *ui.Context) {
	ui.Column(c).Grow(1).MinHeight(0).Gap(12).Children(func() {
		pageBar(c, "连接", "", func() {
			if ui.Button(c, "高级设置").FontSize(11).Clicked() {
				a.openSettingsAt(settingGeneral)
			}
		})
		ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
			a.emptyState(c)
		})
	})
}

// simpleHero 是那张核心卡片：状态、地址、动作、接管方式。
func (a *app) simpleHero(c *ui.Context, v vpn.View) {
	t := c.Theme()
	card := ui.Column(c).Padding(16).Gap(10).Radius(14).Background(t.Surface).
		Border(1, t.Border).Shadow(0, 2, 10, 0, cardShadow(t))
	card.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Row(c).Size(8, 8).Radius(4).Background(stateColor(t, v.State))
			ui.Column(c).Gap(3).Grow(1).MinWidth(0).Children(func() {
				ui.Text(c, v.Name).FontSize(16).Bold().Ellipsis("…")
				ui.Text(c, addrOf(v)).Font("monospace").FontSize(11).
					TextColor(t.TextMuted).Ellipsis("…")
			})
			a.stateBadge(c, v.State)
		})
		if v.State == vpn.StateError && v.Error != "" {
			ui.Text(c, v.Error).FontSize(13).TextColor(t.Danger).Wrap()
		}
		// 登录之后才有的东西：内网 IP 与拨号延迟。
		if v.State == vpn.StateOnline {
			ui.Row(c).GapX(12).GapY(4).Wrap().Children(func() {
				if v.ClientIP != "" {
					meta(c, t, "内网 IP", v.ClientIP)
				}
				if v.Latency >= time.Millisecond {
					meta(c, t, "拨号延迟", v.Latency.Round(time.Millisecond).String())
				}
			})
		}
		a.simpleActions(c, v)
		ui.Divider(c)
		a.simpleCaptureRow(c)
	})
}

// simpleActions 是首屏的动作行：登录 / 断开 / 编辑，加上统一入口地址。
// 统一入口必须露出来——「系统代理」那一档要的就是这个地址。
func (a *app) simpleActions(c *ui.Context, v vpn.View) {
	t := c.Theme()
	agg := a.mgr.Aggregate()
	ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		switch v.State {
		case vpn.StateOnline:
			if ui.Button(c, "断开").Label("断开 " + v.Name).FontSize(11).Clicked() {
				a.disconnectPoint(v.ID)
			}
			if ui.Button(c, "代理浏览器").Label("代理浏览器 " + v.Name).FontSize(11).Clicked() {
				if err := openProxyBrowser(a.proxyFor(v.ID), "about:blank"); err != nil {
					a.setToast(err.Error())
				}
			}
		case vpn.StateConnecting:
			ui.Text(c, "正在接入…").FontSize(11).TextColor(t.Warning)
			if ui.Button(c, "取消").Label("取消 " + v.Name).FontSize(11).Clicked() {
				go a.mgr.Disconnect(v.ID)
			}
		default:
			if ui.PrimaryButton(c, "登录").Label("登录 " + v.Name).FontSize(11).Clicked() {
				a.mgr.Connect(v.ID)
			}
		}
		if ui.Button(c, "编辑").Label("编辑 " + v.Name).FontSize(11).Clicked() {
			a.openEditor(v)
		}
		if agg.Running && agg.Addr != "" {
			addr := "socks5://" + displayAddr(agg.Addr)
			ui.Text(c, addr).Font("monospace").FontSize(11).TextColor(t.TextMuted)
			if ui.Button(c, "复制").Label("复制代理地址").FontSize(11).Clicked() {
				a.copyText(addr)
			}
		} else if agg.Error != "" {
			ui.Text(c, "入口未启动："+agg.Error).FontSize(11).TextColor(t.Danger).
				MaxWidth(220).Ellipsis("…").Tooltip(agg.Error)
		} else {
			ui.Text(c, "入口未启动").FontSize(11).TextColor(t.TextMuted)
		}
	})
}

// simpleCaptureRow 是首屏的接管方式。它走 a.captureModes()：平台或配置做不到的
// 档位照样不出现——简单模式不复制接管逻辑，也不把不可用的档位重新摆出来。
func (a *app) simpleCaptureRow(c *ui.Context) {
	t := c.Theme()
	cur := a.captureMode()
	ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
		ui.Text(c, "网络接管").FontSize(11).Bold().TextColor(t.TextMuted)
		for _, mode := range a.captureModes() {
			it := mode
			on := it == cur
			btn := ui.Row(c).Padding(6, 12).Radius(999).AlignItems(ui.Center).
				Border(1, t.Border)
			if on {
				btn = btn.Background(t.SurfaceHover).Border(1, t.Accent)
			}
			btn.OnClick(func() {
				a.applyCaptureMode(it)
				a.invalidate()
			}).Children(func() {
				colour := t.Text
				if on {
					colour = t.Accent
				}
				ui.Text(c, it).FontSize(11).TextColor(colour)
			})
		}
	})
}

// siteHeading 是「打开内网网站」的小标题；name 非空时补上接入点名，
// 多接入点的「内网网站」页靠它区分磁贴属于谁。
func siteHeading(c *ui.Context, name string) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
		ui.Text(c, "打开内网网站").FontSize(13).Bold()
		if name != "" {
			ui.Text(c, name).FontSize(10).TextColor(t.TextMuted)
		}
		ui.Text(c, "填个网址，用代理浏览器打开").FontSize(10).TextColor(t.TextMuted)
	})
}

// siteAddressField 是那个「填个网址」的输入框与按钮。它全程只有一份：
// 输入框绑定 a.siteURL，多接入点时共用，不能每个接入点各画一个。
func (a *app) siteAddressField(c *ui.Context, open func()) {
	ui.Row(c).Gap(8).AlignItems(ui.End).Children(func() {
		ui.Field(c, "内网地址", func() {
			e := ui.TextInput(c, &a.siteURL).Placeholder("oa.corp.example").Width(300)
			if e.Submitted() {
				open()
			}
		})
		if ui.PrimaryButton(c, "用代理浏览器打开").FontSize(11).Clicked() {
			open()
		}
	})
}

// siteTiles 画这个接入点的磁贴；没有可打开地址时给一句说明。
func (a *app) siteTiles(c *ui.Context, v vpn.View) {
	t := c.Theme()
	tiles := a.simpleSiteTiles(v)
	if len(tiles) == 0 {
		ui.Text(c, "登录之后，网关上能直接打开的地址会出现在这里。").FontSize(11).
			TextColor(t.TextMuted)
		return
	}
	ui.Row(c).Gap(8).Wrap().Children(func() {
		for _, tile := range tiles {
			it := tile
			card := ui.Column(c).Width(220).Padding(10, 12).Radius(12).Gap(3).
				Background(t.Surface).Border(1, t.Border)
			card.OnClick(func() {
				a.openSiteInProxyBrowser(v, it.URL)
				a.invalidate()
			})
			card.Children(func() {
				ui.Text(c, it.Name).FontSize(13).Bold().Ellipsis("…")
				ui.Text(c, it.URL).Font("monospace").FontSize(10).
					TextColor(t.TextMuted).Ellipsis("…")
			})
		}
	})
}

// simpleSites 是简单模式首屏的「打开内网网站」：一个输入框 + 这个接入点的磁贴。
func (a *app) simpleSites(c *ui.Context, v vpn.View) {
	ui.Column(c).Gap(8).Children(func() {
		siteHeading(c, "")
		a.siteAddressField(c, func() { a.openTypedSite(v) })
		a.siteTiles(c, v)
	})
}

// openTypedSite 打开输入框里的地址：空输入只给一句提示，不去开浏览器。
func (a *app) openTypedSite(v vpn.View) {
	target, ok := siteTarget(a.siteURL)
	if !ok {
		a.setToast("先填一个内网地址，例如 oa.corp.example")
		return
	}
	a.openSiteInProxyBrowser(v, target)
}

// sitesPage 是简单模式下的「内网网站」页：输入框只有一份，磁贴按接入点分组。
func (a *app) sitesPage(c *ui.Context) {
	t := c.Theme()
	views := a.mgr.Views()
	ui.Column(c).Grow(1).MinHeight(0).Gap(12).Children(func() {
		pageBar(c, "内网网站", fmt.Sprintf("%d 个接入点", len(views)), func() {
			if ui.Button(c, "高级设置").FontSize(11).Clicked() {
				a.openSettingsAt(settingGeneral)
			}
		})
		ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
			ui.Column(c).Gap(12).Children(func() {
				if len(views) == 0 {
					ui.Text(c, "还没有接入点，先到「连接」页添加一个。").FontSize(13).
						TextColor(t.TextMuted)
					return
				}
				// 输入框按「优先在线的接入点」打开：用户填的地址总得挑一条隧道走。
				a.siteAddressField(c, func() { a.openTypedSite(primaryView(views)) })
				if len(views) == 1 {
					a.siteTiles(c, views[0])
				} else {
					for _, v := range views {
						point := v
						ui.Column(c).Gap(6).Children(func() {
							siteHeading(c, point.Name)
							a.siteTiles(c, point)
						})
					}
				}
				ui.Text(c, "需要端口转发或接管某个软件？在设置里关掉简单模式，"+
					"「本机软件」页就回来了。").FontSize(11).TextColor(t.TextMuted).
					Wrap().MaxWidth(560)
			})
		})
	})
}

// primaryView 挑一个默认用它打开网址的接入点：在线优先，其次第一个。
// 空切片时返回零值，proxyFor 会回统一入口，拿不到就给「先登录」的提示。
func primaryView(views []vpn.View) vpn.View {
	for _, v := range views {
		if v.State == vpn.StateOnline {
			return v
		}
	}
	if len(views) > 0 {
		return views[0]
	}
	return vpn.View{}
}
