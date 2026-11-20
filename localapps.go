package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/localapps"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

type localAppDraft struct {
	open                                                      bool
	id, name, mode, point, executable, url, remote, port, err string
	args, workDir                                             string
	showInstalled                                             bool
	appSearch                                                 string
}

func localModeLabel(mode string) string {
	if mode == model.LocalAppCapture {
		return "软件 TCP 接管"
	}
	if mode == model.LocalAppTCPForward {
		return "数据库 TCP 转发"
	}
	return "代理浏览器"
}

func captureExperimentEnabled() bool {
	return (runtime.GOOS == "linux" || runtime.GOOS == "windows") && os.Getenv("EASYCONNECT_EXPERIMENTAL_CAPTURE") != "0"
}

func localProjectBusy(v localapps.View) bool { return v.Running || v.Starting || v.Stopping }

func (a *app) pointChoice(p model.AccessPoint) string {
	for i, point := range a.cfg.Points {
		if point.ID == p.ID {
			return fmt.Sprintf("%d. %s", i+1, p.Name)
		}
	}
	return p.Name
}

func (a *app) localAppsSection(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Grow(1).MinHeight(0).Gap(10).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "本机软件").FontSize(15).Bold()
			ui.Text(c, fmt.Sprintf("%d 个", len(a.cfg.LocalApps))).FontSize(11).TextColor(t.TextMuted)
			// 提示行占满剩余宽度：窗口窄时先缩它，搜素框与按钮不被挤出去。
			ui.Text(c, localAppsHint()).FontSize(11).TextColor(t.TextMuted).
				Grow(1).MinWidth(0).Ellipsis("…").Tooltip(localAppsHint())
			ui.SearchField(c, &a.localQuery).Placeholder("搜索名称、地址或接入点").
				Label("搜索本机项目").Width(240)
			// 工具栏级按钮跟其他页面保持同一尺寸（13），11 只用于列表行内。
			if ui.PrimaryButton(c, "＋ 添加项目").Clicked() {
				a.openLocalAppEditor("")
			}
		})
		if captureExperimentEnabled() {
			a.captureSetupView(c)
		}
		if len(a.cfg.LocalApps) == 0 {
			a.localAppsEmpty(c)
			return
		}
		// 单栏列表：接入点做分组头，项目嵌套在下面；详情点行进弹窗。
		a.localAppList(c)
	})
}

// localAppsHint 把原来卡片上方的两段说明合成一行提示：解释留在提示行，
// 需要全文时悬停即可，页面不再为它空出两三行。
func localAppsHint() string {
	hint := "先连接 VPN 再启动；统计只计经过项目入口的 TCP 连接，成功表示 TCP 已建立。"
	if captureExperimentEnabled() {
		hint = "先连接 VPN 再启动项目；软件接管需先安装网络助手，仅支持 IPv4 TCP；统计只计经过项目入口的连接。"
		if runtime.GOOS == "windows" {
			hint = "先连接 VPN 再启动项目；Windows 软件 TCP 接管需要管理员授权网络助手，仅支持 IPv4 TCP；统计只计经过项目入口的连接。"
		}
	}
	return hint
}

func (a *app) localAppsEmpty(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Padding(32).Gap(10).Center().Radius(12).Border(1, t.Border).
		Background(t.Surface).Children(func() {
		ui.Text(c, "保存常用入口，下次一键启动").FontSize(15).Bold()
		ui.Text(c, "浏览器可记住起始网址；数据库转发会提供 127.0.0.1 的本地地址。").FontSize(13).TextColor(t.TextMuted).Wrap().MaxWidth(460)
		if ui.PrimaryButton(c, "添加第一个项目").Clicked() {
			a.openLocalAppEditor("")
		}
	})
}

// localGroup 是一个接入点下的本机项目分组。
// 项目本来就绑在接入点上，按接入点分开看比平铺一长串更好找。
type localGroup struct {
	id    string
	name  string
	state vpn.State
	items []model.LocalApp
}

// localGroups 按配置里的接入点顺序分组；找不到接入点的项目归到最后一组，
// 标为已移除，而不是从列表里消失。
func (a *app) localGroups() []localGroup {
	groups := make([]localGroup, 0, len(a.cfg.Points)+1)
	index := map[string]int{}
	for _, point := range a.cfg.Points {
		index[point.ID] = len(groups)
		g := localGroup{id: point.ID, name: point.Name, state: vpn.StateOffline}
		if v, ok := a.mgr.View(point.ID); ok {
			g.state = v.State
		}
		groups = append(groups, g)
	}
	orphan := -1
	for _, p := range a.cfg.LocalApps {
		i, ok := index[p.PointID]
		if !ok {
			if orphan < 0 {
				orphan = len(groups)
				groups = append(groups, localGroup{name: "接入点已删除"})
			}
			i = orphan
		}
		groups[i].items = append(groups[i].items, p)
	}
	return groups
}

// localAppList 是单栏列表：接入点当分组头，项目嵌在下面，行间发丝分隔。
// 搜索时忽略折起状态，命中的分组自动展开，否则搜到东西也看不到。
func (a *app) localAppList(c *ui.Context) {
	t := c.Theme()
	query := strings.TrimSpace(a.localQuery)
	groups := a.localGroupsMatching(query)
	panel := ui.Column(c).Grow(1).Radius(12).Border(1, t.Border).
		Background(t.Surface)
	panel.Children(func() {
		ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(8, 6, 8, 4).Children(func() {
			if len(groups) == 0 {
				noResults(c, "没有匹配的项目",
					"换个名称、地址或接入点试试；清空搜索可以看到全部项目。")
				return
			}
			first := true
			for _, g := range groups {
				if !first {
					ui.Divider(c)
				}
				first = false
				// 搜索时全部展开，不然命中的项目还被折在组里。
				collapsed := a.localCollapsed[g.id] && query == ""
				a.localGroupHeader(c, g, collapsed)
				if collapsed {
					continue
				}
				for _, p := range g.items {
					ui.Divider(c)
					a.localAppRow(c, p)
				}
			}
		})
	})
}

// localGroupsMatching 按名称、方式、目标或接入点名过滤项目，空的组不返回。
func (a *app) localGroupsMatching(query string) []localGroup {
	q := strings.ToLower(strings.TrimSpace(query))
	groups := a.localGroups()
	if q == "" {
		out := groups[:0]
		for _, g := range groups {
			if len(g.items) > 0 {
				out = append(out, g)
			}
		}
		return out
	}
	out := make([]localGroup, 0, len(groups))
	for _, g := range groups {
		var items []model.LocalApp
		for _, p := range g.items {
			hay := strings.ToLower(p.Name + " " + localModeLabel(p.Mode) + " " +
				localTargetLine(p) + " " + g.name)
			if strings.Contains(hay, q) {
				items = append(items, p)
			}
		}
		if len(items) > 0 {
			g.items = items
			out = append(out, g)
		}
	}
	return out
}

// localGroupHeader 是接入点分组头：状态灯、名称、状态和项目数，整行可点。
func (a *app) localGroupHeader(c *ui.Context, g localGroup, collapsed bool) {
	t := c.Theme()
	state := g.state.Label()
	if g.id == "" {
		state = "已移除"
	}
	groupBar(c, collapsed, stateColor(t, g.state), g.name, state,
		fmt.Sprintf("%d 个项目", len(g.items)), func() {
			if a.localCollapsed == nil {
				a.localCollapsed = map[string]bool{}
			}
			a.localCollapsed[g.id] = !collapsed
			a.invalidate()
		}, nil)
}

func (a *app) localAppRow(c *ui.Context, p model.LocalApp) {
	t := c.Theme()
	v := a.localView(p.ID)
	online, _ := a.localPointOnline(p)
	status, tone := localStatusText(t, p, v, online)
	row := ui.Row(c).Padding(10, 12).Gap(10).AlignItems(ui.Center).Radius(8)
	row.OnClick(func() {
		a.openLocalAppEditor(p.ID)
	})
	if row.Hovered() {
		row = row.Background(t.SurfaceHover)
	}
	row.Children(func() {
		localModeMark(c, t, p.Mode, p.Name)
		ui.Column(c).Gap(3).Grow(1).MinWidth(0).Children(func() {
			ui.Text(c, p.Name).FontSize(13).Bold().Ellipsis("…")
			// 接入点已经写在分组头上，行里只留目标与方式。
			ui.Text(c, localModeLabel(p.Mode)+" · "+localTargetLine(p)).FontSize(11).
				TextColor(t.TextMuted).Ellipsis("…")
		})
		ui.Text(c, status).FontSize(11).TextColor(tone).Ellipsis("…")
		// 行里只放一个常用动作，其余详情、编辑、删除都在弹窗里。
		switch {
		case !localProjectBusy(v):
			if ui.PrimaryButton(c, "启动").Label("启动 " + p.Name).FontSize(11).Clicked() {
				a.startLocalApp(p.ID)
			}
		case v.Stopping:
			// 停止过程中不给按钮，行上已经写了状态。
		case p.Mode == model.LocalAppBrowser:
			// 浏览器在独立窗口里关，列表不提供停止。
		default:
			label := "停止"
			if v.Starting {
				label = "取消"
			}
			if ui.Button(c, label).Label(label + " " + p.Name).FontSize(11).Clicked() {
				go func() { _ = a.local.Stop(p.ID) }()
			}
		}
	})
}

func (a *app) localView(id string) localapps.View {
	if a.local == nil {
		return localapps.View{}
	}
	return a.local.View(id)
}

// localPointOnline reports whether the project's access point is connected,
// and the point name to show for it.
func (a *app) localPointOnline(p model.LocalApp) (bool, string) {
	point := a.cfg.Find(p.PointID)
	if point == nil {
		return false, "接入点已删除，请重新选择"
	}
	if state, ok := a.mgr.View(point.ID); ok {
		return state.State == vpn.StateOnline, point.Name
	}
	return false, point.Name
}

// localStatusText is the one-line state shown in the project list. It follows
// the same precedence the detail card used: a missing VPN wins over progress.
func localStatusText(t *ui.Theme, p model.LocalApp, v localapps.View, online bool) (string, ui.Color) {
	status := "未启动"
	tone := t.TextMuted
	if v.Running {
		status = "运行中"
		tone = t.Success
		if p.Mode == model.LocalAppCapture {
			status = "TCP 接管中"
		}
	}
	if v.Starting {
		status = "正在准备接管…"
		tone = t.Warning
	}
	if v.Stopping {
		status = "正在停止…"
		tone = t.Warning
	}
	if !online {
		status = "VPN 未连接"
		tone = t.Warning
	}
	if v.Error != "" {
		status += " · 需处理"
		tone = t.Danger
	}
	return status, tone
}

// localTargetLine is the address line under a project's name: the start URL, the
// executable, or the remote target of a fixed local port.
func localTargetLine(p model.LocalApp) string {
	switch p.Mode {
	case model.LocalAppBrowser:
		return p.URL
	case model.LocalAppCapture:
		return p.Executable
	default:
		if p.ListenPort > 0 {
			return p.RemoteAddress + " → 127.0.0.1:" + strconv.Itoa(p.ListenPort)
		}
		return p.RemoteAddress
	}
}

func localModeMark(c *ui.Context, t *ui.Theme, mode, name string) {
	tint := t.Accent
	switch mode {
	case model.LocalAppTCPForward:
		tint = t.Success
	case model.LocalAppCapture:
		tint = t.Warning
	}
	ui.Row(c).Size(28, 28).Radius(9).Background(t.Surface).Border(1, t.Border).
		AlignItems(ui.Center).Justify(ui.Center).Children(func() {
		ui.Text(c, firstRune(name)).FontSize(13).Bold().TextColor(tint)
	})
}

// localAppStatusBlock 在编辑器顶部给出这个项目当前的运行情况：
// 列表里看不到的本地地址、TCP 统计与错误都在这里，不用再多一层详情弹窗。
func (a *app) localAppStatusBlock(c *ui.Context, p model.LocalApp) {
	t := c.Theme()
	v := a.localView(p.ID)
	online, pointName := a.localPointOnline(p)
	status, tone := localStatusText(t, p, v, online)
	box := ui.Column(c).Padding(10, 12).Gap(6).Radius(12).
		Border(1, t.Border).Background(t.Surface)
	box.Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, status).FontSize(11).TextColor(tone)
			ui.Text(c, "接入点 "+pointName).FontSize(11).TextColor(t.TextMuted).Ellipsis("…")
			ui.Row(c).Grow(1)
			if v.Running && v.LocalAddress != "" {
				ui.Text(c, v.LocalAddress).Font("monospace").FontSize(11)
				if ui.Button(c, "复制地址").Label("复制转发地址 " + p.ID).FontSize(11).Clicked() {
					a.copyText(v.LocalAddress)
				}
			}
		})
		if v.Observed {
			s := v.Connections
			ui.Text(c, fmt.Sprintf("TCP 连接：%d 活跃 · %d 连接中 · %d 成功 · %d 失败 · 发送 %s · 接收 %s",
				s.Active, s.Connecting, s.Opened, s.Failed,
				trafficBytes(s.Sent), trafficBytes(s.Received))).
				FontSize(11).TextColor(t.TextMuted).Wrap()
		}
		if p.Mode == model.LocalAppCapture && v.Running {
			dnsText := "网关未提供内网域名后缀，DNS 使用当前系统配置。"
			if v.DNSDomains > 0 {
				dnsText = fmt.Sprintf("已启用 %d 个内网 DNS 后缀；这些域名的系统解析由其他软件共享。", v.DNSDomains)
			}
			ui.Text(c, dnsText).FontSize(11).TextColor(t.TextMuted).Wrap()
		}
		if v.Error != "" {
			ui.Text(c, v.Error).FontSize(11).TextColor(t.Danger).Wrap()
		}
	})
}

func (a *app) openLocalAppEditor(id string) {
	if a.local != nil && localProjectBusy(a.local.View(id)) {
		a.toast = "请先停止项目或关闭独立浏览器，再编辑"
		return
	}
	d := localAppDraft{open: true, mode: localModeLabel(model.LocalAppBrowser), port: "0"}
	if len(a.cfg.Points) > 0 {
		d.point = a.pointChoice(a.cfg.Points[0])
	}
	if p := a.cfg.FindLocalApp(id); p != nil {
		d.id, d.name, d.mode = p.ID, p.Name, localModeLabel(p.Mode)
		d.executable, d.url, d.remote, d.port = p.Executable, p.URL, p.RemoteAddress, strconv.Itoa(p.ListenPort)
		d.workDir = p.WorkDir
		if len(p.Args) > 0 {
			b, _ := json.Marshal(p.Args)
			d.args = string(b)
		}
		if point := a.cfg.Find(p.PointID); point != nil {
			d.point = a.pointChoice(*point)
		}
	}
	a.localEditor = d
}

func (a *app) localAppEditorView(c *ui.Context) {
	d := &a.localEditor
	if !d.open {
		return
	}
	t := c.Theme()
	ui.Modal(c, &d.open, func() {
		ui.Column(c).Width(dialogWide).Gap(10).Children(func() {
			title := "添加本机项目"
			if d.id != "" {
				title = "编辑本机项目"
			}
			dialogHeader(c, title, "点列表里的项目就能回到这里；改动配置前请先停止项目或关闭浏览器窗口。")
			if d.id != "" {
				if p := a.cfg.FindLocalApp(d.id); p != nil {
					a.localAppStatusBlock(c, *p)
				}
			}
			ui.Scroll(c).MaxHeight(a.dialogBodyHeight(380)).MinHeight(0).
				ScrollbarInsets(6, 6, 6, 6).Children(func() {
				ui.Column(c).Gap(10).Children(func() {
					ui.Field(c, "项目名称", func() { ui.TextInput(c, &d.name).Placeholder("例如：工作浏览器 / 开发数据库") })
					ui.Field(c, "接入方式", func() {
						modes := []string{localModeLabel(model.LocalAppBrowser), localModeLabel(model.LocalAppTCPForward)}
						if captureExperimentEnabled() || d.mode == localModeLabel(model.LocalAppCapture) {
							modes = append(modes, localModeLabel(model.LocalAppCapture))
						}
						ui.Select(c, &d.mode, modes)
					})
					choices := make([]string, 0, len(a.cfg.Points))
					for _, p := range a.cfg.Points {
						choices = append(choices, a.pointChoice(p))
					}
					ui.Field(c, "使用的 VPN", func() {
						if len(choices) == 0 {
							ui.Text(c, "请先添加一个 VPN 接入点").TextColor(t.Warning)
						} else {
							ui.Select(c, &d.point, choices)
						}
					})
					if d.mode == localModeLabel(model.LocalAppBrowser) {
						ui.Field(c, "起始网址", func() { ui.TextInput(c, &d.url).Placeholder("https://portal.internal/，留空打开空白页") })
						ui.Field(c, "浏览器可执行文件", func() {
							ui.Row(c).Gap(8).Children(func() {
								ui.TextInput(c, &d.executable).Placeholder("留空自动查找 Chrome / Edge / Chromium").Grow(1)
								if ui.Button(c, "浏览…").FontSize(11).Clicked() {
									paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "选择 Chromium 浏览器可执行文件"})
									if err != nil {
										d.err = err.Error()
									} else if len(paths) > 0 {
										d.executable = paths[0]
									}
								}
							})
						})
						ui.Text(c, "使用独立浏览器配置；当前支持 Chromium 系列。已打开的普通浏览器不受此项目控制。").FontSize(11).TextColor(t.TextMuted).Wrap()
					} else if d.mode == localModeLabel(model.LocalAppCapture) {
						a.installedAppsPicker(c)
						ui.Field(c, "软件可执行文件", func() {
							ui.Row(c).Gap(8).Children(func() {
								ui.TextInput(c, &d.executable).Placeholder("选择 IDEA、数据库工具等程序").Grow(1)
								if ui.Button(c, "浏览…").FontSize(11).Clicked() {
									paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.win, Title: "选择软件可执行文件"})
									if err != nil {
										d.err = err.Error()
									} else if len(paths) > 0 {
										d.executable = paths[0]
									}
								}
							})
						})
						ui.Field(c, "启动参数（可选，JSON 数组）", func() { ui.TextInput(c, &d.args).Placeholder(`["--new-window", "http://10.0.0.1/"]`) })
						ui.Field(c, "工作目录（可选）", func() { ui.TextInput(c, &d.workDir).Placeholder("留空使用当前目录") })
					} else {
						ui.Field(c, "数据库远端地址", func() { ui.TextInput(c, &d.remote).Placeholder("db.internal:5432 或 10.0.0.10:3306") })
						ui.Field(c, "本地端口", func() { ui.TextInput(c, &d.port).Placeholder("0 表示自动分配") })
						ui.Text(c, "启动后将显示本地连接地址，填入数据库工具即可。只转发这一个 TCP 目标；无需提供数据库密码。").FontSize(11).TextColor(t.TextMuted).Wrap()
					}
				})
			})
			if d.mode == localModeLabel(model.LocalAppCapture) {
				note := "请先保存工作并关闭已有实例。启动前检查同一可执行文件的运行实例；脚本包装器、已有后台服务和 D-Bus 启动仍需自行确认。实验接管 IPv4 TCP，内网 UDP/IPv6 与 Flatpak 暂不支持。"
				if runtime.GOOS == "windows" {
					note = "请先保存工作并退出已有实例。接管所选 .exe 和新建的常规子进程，已有后台服务及需要管理员权限的软件暂不支持。停止接管会保留软件进程。仅支持 IPv4 TCP；首次使用需要实机验证。"
				}
				ui.Text(c, note).FontSize(11).TextColor(t.Warning).Wrap()
			}
			if d.err != "" {
				ui.Text(c, d.err).FontSize(11).TextColor(t.Danger).Wrap()
			}
			dialogFooter(c, func() {
				if d.id != "" && ui.Button(c, "删除项目").FontSize(11).Clicked() {
					a.localDelete = d.id
					d.open = false
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").Label("取消本机项目").FontSize(11).Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "保存").Label("保存本机项目").FontSize(11).Clicked() {
					a.saveLocalApp()
				}
			})
		})
	})
}

func (a *app) saveLocalApp() {
	d := &a.localEditor
	p := model.LocalApp{ID: d.id, Name: d.name, Mode: model.LocalAppBrowser}
	if p.ID == "" {
		p.ID = model.NewID()
	}
	for _, point := range a.cfg.Points {
		if a.pointChoice(point) == d.point {
			p.PointID = point.ID
			break
		}
	}
	if d.mode == localModeLabel(model.LocalAppTCPForward) {
		p.Mode = model.LocalAppTCPForward
		p.RemoteAddress = d.remote
		port, err := parseOptionalPort(d.port)
		if err != nil {
			d.err = "本地端口：" + err.Error()
			return
		}
		p.ListenPort = port
	} else if d.mode == localModeLabel(model.LocalAppCapture) {
		p.Mode = model.LocalAppCapture
		p.Executable = d.executable
		p.WorkDir = d.workDir
		if strings.TrimSpace(d.args) != "" {
			if err := json.Unmarshal([]byte(d.args), &p.Args); err != nil {
				d.err = "启动参数应为字符串数组，例如 [\"--new-window\"]"
				return
			}
		}
	} else {
		p.URL = d.url
		p.Executable = d.executable
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		d.err = err.Error()
		return
	}
	if a.local != nil && localProjectBusy(a.local.View(p.ID)) {
		d.err = "请先停止项目再保存"
		return
	}
	_, err := a.store.Update(func(cfg *model.Config) error {
		if cfg.Find(p.PointID) == nil {
			return errors.New("所选接入点已不存在")
		}
		if current := cfg.FindLocalApp(p.ID); current != nil {
			*current = p
		} else {
			cfg.LocalApps = append(cfg.LocalApps, p)
		}
		return nil
	})
	if err == nil {
		err = a.saveConfig()
	}
	if err != nil {
		d.err = "保存失败：" + err.Error()
		return
	}
	d.open = false
	a.toast = "已保存「" + p.Name + "」"
}

func (a *app) localAppDeleteView(c *ui.Context) {
	if a.localDelete == "" {
		return
	}
	open := true
	ui.Modal(c, &open, func() {
		ui.Column(c).Width(dialogNarrow).Gap(10).Children(func() {
			dialogHeader(c, "删除这个本机项目？", "只删配置，不影响已经打开的程序；需要的话之后可以重新添加。")
			dialogFooter(c, func() {
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").FontSize(11).Clicked() {
					a.localDelete = ""
				}
				if ui.Button(c, "确认删除").FontSize(11).Clicked() {
					id := a.localDelete
					_, err := a.store.Update(func(cfg *model.Config) error {
						if a.local != nil && localProjectBusy(a.local.View(id)) {
							return errors.New("请先停止项目")
						}
						for i, p := range cfg.LocalApps {
							if p.ID == id {
								cfg.LocalApps = append(cfg.LocalApps[:i], cfg.LocalApps[i+1:]...)
								break
							}
						}
						return nil
					})
					if err == nil {
						err = a.saveConfig()
					}
					if err != nil {
						a.toast = err.Error()
					}
					a.localDelete = ""
				}
			})
		})
	})
	if !open {
		a.localDelete = ""
	}
}

// localProxyFor deliberately requires one online point's dedicated listener;
// the aggregate proxy could choose a different gateway.
func (a *app) localProxyFor(pointID string) (string, error) {
	v, ok := a.mgr.View(pointID)
	if !ok || v.State != vpn.StateOnline {
		return "", errors.New("请先登录所选 VPN 接入点")
	}
	if v.SocksPort <= 0 {
		return "", errors.New("请在所选接入点的设置中开启独立 HTTP / SOCKS5 端口")
	}
	host := a.cfg.Settings.ListenHost
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("本机软件需要监听地址为回环地址，请在设置中使用 127.0.0.1")
	}
	return net.JoinHostPort(host, strconv.Itoa(v.SocksPort)), nil
}

func (a *app) startLocalApp(id string) {
	p := a.cfg.FindLocalApp(id)
	if p == nil || a.local == nil {
		return
	}
	profile := *p
	if profile.Mode == model.LocalAppBrowser && strings.TrimSpace(profile.Executable) == "" {
		profile.Executable = findChromium()
		if profile.Executable == "" {
			a.toast = "没有找到 Chrome / Edge / Chromium，请编辑项目选择浏览器"
			return
		}
	}
	a.localLife.Lock()
	defer a.localLife.Unlock()
	if profile.Mode == model.LocalAppCapture {
		if !captureExperimentEnabled() {
			a.toast = "软件 TCP 接管支持 Linux 和 Windows；如设置了 EASYCONNECT_EXPERIMENTAL_CAPTURE=0，请取消后重新启动应用"
			return
		}
		if a.captureSetupBusy() {
			a.toast = "正在安装辅助服务，请等待完成后再启动软件"
			return
		}
		connection, err := a.mgr.LocalAppConnection(profile.PointID)
		if err == nil {
			var domains []string
			domains, err = localapps.DNSDomains(connection.Resources)
			if err == nil {
				config := localapps.CaptureConfig{Key: connection.Key, Identity: connection.Identity, Domains: domains, Exchange: connection.DNS, MappedDNS: connection.MappedDNS, ConfirmAliases: connection.ConfirmAliases, BeginPublication: connection.BeginPublication, ReservedPools: connection.ReservedPools, AliasNetworks: connection.AliasNetworks, Active: connection.Active}
				config.SelectDNS = connection.SelectDNS
				if point := a.cfg.Find(profile.PointID); point != nil {
					config.Gateway = point.Server
				}
				config.Networks, err = localapps.CaptureNetworks(connection.Resources)
				if err == nil {
					err = a.local.StartCapture(profile, connection.Dial, connection.Active, config)
				}
			}
		}
		if err != nil {
			a.toast = err.Error()
			a.logLocalAppError(profile.Name, err)
		} else {
			a.toast = "正在准备「" + profile.Name + "」的 TCP 接管"
		}
		return
	}
	connection, err := a.mgr.LocalAppConnection(profile.PointID)
	if err == nil {
		err = a.local.Start(profile, "", localapps.Connection{Dial: connection.Dial, Active: connection.Active})
	}
	if err != nil {
		a.toast = err.Error()
		return
	}
	a.toast = fmt.Sprintf("已启动「%s」", profile.Name)
}

func (a *app) reconcileLocalApps() {
	if a.local == nil || a.mgr == nil {
		return
	}
	a.local.StopExpiredCaptures()
	for _, v := range a.local.Views() {
		if !localProjectBusy(v) || v.Mode == model.LocalAppBrowser {
			continue
		}
		point, ok := a.mgr.View(v.PointID)
		if !ok || point.State != vpn.StateOnline {
			a.local.StopPoint(v.PointID)
		}
	}
}
