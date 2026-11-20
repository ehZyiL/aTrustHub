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
			ui.Text(c, "本机软件").FontSize(18).Bold()
			ui.Row(c).Grow(1)
			if ui.PrimaryButton(c, "＋ 添加项目").Clicked() {
				a.openLocalAppEditor("")
			}
		})
		intro := "先连接 VPN，再启动浏览器或数据库转发。普通软件及子进程的透明接管仍在开发。"
		if captureExperimentEnabled() {
			intro = "先连接 VPN，再添加并启动软件。软件 TCP 接管需安装辅助服务；内网 UDP/IPv6 暂不支持。"
			if runtime.GOOS == "windows" {
				intro = "先连接 VPN，再添加并启动软件。Windows 软件 TCP 接管需要管理员授权网络助手；内网 UDP/IPv6 暂不支持。"
			}
		}
		ui.Text(c, intro).FontSize(12).TextColor(t.TextMuted).Wrap()
		ui.Text(c, "统计仅包含经过项目入口的 TCP 连接；成功表示 TCP 已建立。每次重新启动项目会重新计数。").FontSize(11).TextColor(t.TextMuted).Wrap()
		if captureExperimentEnabled() {
			a.captureSetupView(c)
		}
		ui.Scroll(c).Grow(1).MinHeight(0).Children(func() {
			ui.Column(c).Gap(12).Children(func() {
				if len(a.cfg.LocalApps) == 0 {
					ui.Column(c).Padding(24).Gap(10).Children(func() {
						ui.Text(c, "保存常用入口，下次一键启动").FontSize(16).Bold()
						ui.Text(c, "浏览器可记住起始网址；数据库转发会提供 127.0.0.1 的本地地址。").FontSize(12).TextColor(t.TextMuted).Wrap()
					})
				}
				for _, p := range a.cfg.LocalApps {
					a.localAppCard(c, p)
				}
			})
		})
	})
}

func (a *app) localAppCard(c *ui.Context, p model.LocalApp) {
	t := c.Theme()
	v := localapps.View{}
	if a.local != nil {
		v = a.local.View(p.ID)
	}
	point := a.cfg.Find(p.PointID)
	pointName := "接入点已删除，请重新选择"
	online := false
	if point != nil {
		pointName = point.Name
		if state, ok := a.mgr.View(point.ID); ok {
			online = state.State == vpn.StateOnline
		}
	}
	ui.Column(c).Padding(16).Gap(8).Radius(10).Border(1, t.Border).Background(t.Surface).Children(func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, p.Name).FontSize(15).Bold().Grow(1).Ellipsis("…")
			ui.Badge(c, localModeLabel(p.Mode))
			status := "未启动"
			if v.Running {
				status = "运行中"
				if p.Mode == model.LocalAppCapture {
					status = "TCP 接管中"
				}
			}
			if v.Starting {
				status = "正在准备接管…"
			}
			if v.Stopping {
				status = "正在停止…"
			}
			if !online {
				status = "VPN 未连接"
			}
			ui.Text(c, status).FontSize(12).TextColor(t.TextMuted)
		})
		ui.Text(c, "接入点："+pointName).FontSize(12).TextColor(t.TextMuted)
		if p.Mode == model.LocalAppBrowser {
			ui.Text(c, "起始网址："+p.URL).FontSize(12).Ellipsis("…")
		} else if p.Mode == model.LocalAppCapture {
			ui.Text(c, "程序："+p.Executable).FontSize(12).Ellipsis("…")
			ui.Text(c, "覆盖此次启动及普通新子进程。停止接管后软件继续运行，新连接恢复系统网络。").FontSize(11).TextColor(t.TextMuted).Wrap()
			if v.Running {
				dnsText := "网关未提供内网域名后缀，DNS 使用当前系统配置。"
				if v.DNSDomains > 0 {
					dnsText = fmt.Sprintf("已启用 %d 个内网 DNS 后缀；这些域名的系统解析由其他软件共享。", v.DNSDomains)
				}
				ui.Text(c, dnsText).FontSize(11).TextColor(t.TextMuted).Wrap()
			}
		} else {
			ui.Text(c, "远端："+p.RemoteAddress).FontSize(12)
			if v.Running {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "本地连接地址："+v.LocalAddress).FontSize(13).Bold()
					if ui.Button(c, "复制地址").Label("复制转发地址 " + p.ID).Clicked() {
						a.copyText(v.LocalAddress)
					}
				})
				ui.Text(c, "在数据库工具中使用此本地地址。TLS 的服务器名称仍应按远端服务配置。").FontSize(11).TextColor(t.TextMuted).Wrap()
			}
		}
		if v.Observed {
			s := v.Connections
			ui.Text(c, fmt.Sprintf("TCP 连接：%d 活跃 · %d 连接中 · %d 成功 · %d 失败", s.Active, s.Connecting, s.Opened, s.Failed)).FontSize(12).Wrap()
			ui.Text(c, fmt.Sprintf("发送 %s · 接收 %s · 路径和规则见「访问日志」", trafficBytes(s.Sent), trafficBytes(s.Received))).FontSize(11).TextColor(t.TextMuted).Wrap()
		}
		if v.Error != "" {
			ui.Text(c, v.Error).FontSize(12).TextColor(t.Danger).Wrap()
		}
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			if !localProjectBusy(v) {
				if ui.PrimaryButton(c, "启动").Label("启动本机项目 " + p.ID).Clicked() {
					a.startLocalApp(p.ID)
				}
			} else if v.Stopping {
				ui.Text(c, "正在清理此项目的网络入口…").FontSize(11).TextColor(t.TextMuted)
			} else if p.Mode == model.LocalAppCapture {
				label := "停止接管"
				if v.Starting {
					label = "取消启动"
				}
				if ui.Button(c, label).Label("停止本机项目 " + p.ID).Clicked() {
					go func() { _ = a.local.Stop(p.ID) }()
				}
			} else if p.Mode == model.LocalAppTCPForward {
				if ui.Button(c, "停止转发").Label("停止本机项目 " + p.ID).Clicked() {
					go func() { _ = a.local.Stop(p.ID) }()
				}
			} else {
				ui.Text(c, "请在独立浏览器窗口中关闭；关闭后可重新启动。").FontSize(11).TextColor(t.TextMuted).Wrap()
			}
			ui.Row(c).Grow(1)
			if ui.Button(c, "编辑").Label("编辑本机项目 " + p.ID).Clicked() {
				a.openLocalAppEditor(p.ID)
			}
		})
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
		ui.Column(c).Width(600).Gap(10).Children(func() {
			title := "添加本机项目"
			if d.id != "" {
				title = "编辑本机项目"
			}
			ui.Text(c, title).FontSize(18).Bold()
			ui.Scroll(c).MaxHeight(390).MinHeight(0).Children(func() {
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
								if ui.Button(c, "浏览…").Clicked() {
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
								if ui.Button(c, "浏览…").Clicked() {
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
				ui.Text(c, d.err).FontSize(12).TextColor(t.Danger).Wrap()
			}
			ui.Row(c).Gap(8).Children(func() {
				if d.id != "" && ui.Button(c, "删除项目").Clicked() {
					a.localDelete = d.id
					d.open = false
				}
				ui.Row(c).Grow(1)
				if ui.Button(c, "取消").Label("取消本机项目").Clicked() {
					d.open = false
				}
				if ui.PrimaryButton(c, "保存").Label("保存本机项目").Clicked() {
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
		ui.Column(c).Width(420).Gap(12).Children(func() {
			ui.Text(c, "删除这个本机项目？").FontSize(17).Bold()
			ui.Row(c).Gap(8).Justify(ui.End).Children(func() {
				if ui.Button(c, "取消").Clicked() {
					a.localDelete = ""
				}
				if ui.Button(c, "确认删除").Clicked() {
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
				config := localapps.CaptureConfig{Key: connection.Key, Domains: domains, Exchange: connection.DNS, MappedDNS: connection.MappedDNS, Active: connection.Active}
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
