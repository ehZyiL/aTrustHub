package desktop

import (
	"errors"
	"fmt"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	pageBar(c, "网关资源", fmt.Sprintf("%d 个", len(all)), func() {
		if ui.Button(c, "网络授权与路由").FontSize(12).Clicked() {
			a.openRoutes()
		}
	})
	ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
		ui.SearchField(c, &a.appQuery).Placeholder("搜索资源名称、地址或标签").
			Label("搜索资源").Grow(1).MinWidth(0)
		ui.Segmented(c, &a.appFilterIndex, "所有", "已启用", "未启用").Label("过滤资源")
	})
	a.appFilter = appFilterValue(a.appFilterIndex)
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

	scroll := ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(6, 2, 6, 0)
	scroll.Children(func() {
		ui.Column(c).Padding(0, 12, 0, 0).Gap(14).Children(func() {
			if len(all) == 0 {
				a.appsEmpty(c)
				return
			}
			if len(shown) == 0 {
				noResults(c, "没有匹配的资源", "试试其他名称、地址或标签，或切换启用状态筛选。")
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
				collapsed := a.appCollapsed[pid] && query == ""
				ui.Column(c).Gap(8).Children(func() {
					// 一组资源装在一个面板里：分组头是面板顶部的一条色带，行间用发丝分隔。
					panel := ui.Column(c).Radius(8).Border(1, t.Border).
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
		ui.Text(c, "可点击接入点卡片打开代理浏览器，也可以为软件手动配置代理。").
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

// appRow 是资源页的一行：字母槽、名称与地址、类型、隧道代理开关和详情入口。
// 行式密度让上百个资源能一屏扫过；分类、描述与停用状态都挤在副标题里。
func (a *app) appRow(c *ui.Context, entry appEntry) {
	t := c.Theme()
	app := entry.App
	enabled := a.appEnabled(entry.PointID, app.ID)
	row := ui.Row(c).Padding(10, 14).Gap(10).AlignItems(ui.Center).Radius(8).
		OnClick(func() { a.openAppDetail(entry) })
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
		ui.Text(c, app.TypeLabel()).FontSize(12).TextColor(t.TextMuted)
		a.appTunnelSwitch(c, entry)
		ui.Text(c, "›").FontSize(16).TextColor(t.TextMuted).Tooltip("查看资源详情")
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
	// 简单模式只有统一入口这一个代理地址：每点端口不再参与，但也不去改它
	// （改 SocksPort 会让 Manager 重建在线的隧道）。
	if !a.simpleMode() {
		if p := a.cfg.Find(pointID); p != nil && p.SocksPort > 0 {
			return displayAddr(net.JoinHostPort(a.cfg.Settings.ListenHost, strconv.Itoa(p.SocksPort)))
		}
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
	if a.tunOn.Load() && hostInTun(a.tunPoints, id) {
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
