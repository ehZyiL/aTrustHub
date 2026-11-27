package desktop

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"strings"
)

type settingsDraft struct {
	open bool
	// section 是设置页的当前分区（通用/网络与接管/日志/关于）。
	section int
	// mode 是接管方式下拉的绑定值，每帧从真实状态回读。
	mode string
	// autoRestoreAppCapture 是「启动/登录后自动恢复应用接管」的草稿值。
	autoRestoreAppCapture bool
	// appearance 是颜色模式下拉的草稿值（跟随系统 / 浅色 / 深色）。
	appearance string
	// theme 是主题色系的草稿值（blue / green / purple）。
	theme string
	// quitOnClose 是「关闭主窗口时退出程序」的草稿值（仅 Windows）。
	quitOnClose bool
	host        string
	port        string
	// proxyUser / proxyPass guard the listeners when host is not loopback.
	proxyUser     string
	proxyPass     string
	interval      string
	routing       string
	aggregate     bool
	autoReconnect bool
	secretStore   string
	// hideDock hides the macOS Dock icon; the menu bar icon takes over.
	hideDock bool
	// simpleMode 是简单模式开关的绑定值。它只是界面绑定：真正的持久化与
	// 概念收敛在 setSimpleMode 里，所以它不参与 settingsDirty。
	simpleMode      bool
	autoCheckUpdate bool
	err             string
}

// 设置页的分区编号：多 tab 共用这一个字段。
const (
	settingGeneral = iota
	settingNetwork
	settingLogs
	settingAbout
	settingMaintenance
)

// settingsPage 是整页设置：顶部切换分区，改动即时生效。
// 原来散在页脚与顶栏的东西——版本、数据目录、运行日志、退出、接管开关——
// 全部收进这里，主界面因此只剩导航与内容。
func (a *app) settingsPage(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	ui.Column(c).Grow(1).MinHeight(0).Gap(10).Children(func() {
		pageBar(c, "设置", "", func() {
			if d.section == settingGeneral || d.section == settingNetwork {
				ui.Text(c, "改动即时生效").FontSize(12).TextColor(t.TextMuted)
			}
			if ui.Button(c, "返回").Label("关闭设置").FontSize(12).Clicked() {
				d.open = false
			}
		})
		ui.Row(c).Children(func() {
			labels := []string{"通用", "网络与接管", "日志", "关于"}
			if supportsCleanup() {
				labels = append(labels, "维护")
			}
			ui.Segmented(c, &d.section, labels...).Label("设置分类").Background(t.SurfaceHover).Radius(8)
		})
		ui.Divider(c)
		ui.Scroll(c).Grow(1).MinHeight(0).ScrollbarInsets(6, 2, 6, 0).Children(func() {
			ui.Column(c).Padding(0, 12, 0, 0).Gap(10).Children(func() {
				switch d.section {
				case settingNetwork:
					a.captureSection(c)
				case settingLogs:
					a.logsSection(c)
				case settingAbout:
					a.aboutSection(c)
				case settingMaintenance:
					a.maintenanceSection(c)
				default:
					a.generalSection(c)
				}
			})
		})
		if d.err != "" {
			ui.Text(c, d.err).FontSize(11).TextColor(t.Danger)
		}
	})
}

// generalSection 是原来的设置弹窗内容，按整页排版重新分好组。
// 简单模式下只保留外观与日常开关，专业项收起来（开关就在最上面）。
func (a *app) generalSection(c *ui.Context) {
	settingsGroup(c, "显示与主题", func() {
		a.simpleModeField(c)
		a.appearanceFields(c)
	})
	settingsGroup(c, "启动与连接", func() {
		a.commonSwitches(c)
	})
	a.lanShareSection(c)
	if !a.simpleMode() {
		settingsGroup(c, "代理与分流", func() {
			a.proxySettings(c)
		})
	}
}

func settingsGroup(c *ui.Context, title string, content func()) {
	t := c.Theme()
	ui.Column(c).Padding(12, 14).Gap(10).Radius(8).Border(1, t.Border).
		Background(t.Surface).Children(func() {
		ui.Text(c, title).FontSize(14).Bold()
		content()
	})
}

func (a *app) proxySettings(c *ui.Context) {
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
	if !model.IsLoopbackHost(strings.TrimSpace(d.host)) {
		ui.Row(c).Gap(12).AlignItems(ui.End).Wrap().Children(func() {
			ui.Field(c, "代理用户名", func() {
				e := ui.TextInput(c, &d.proxyUser).Placeholder(model.ProxyUsernameDefault).Width(150)
				if e.Submitted() || e.PressedOutside() {
					a.applySettingsIfChanged()
				}
			})
			ui.Field(c, "代理密码", func() {
				e := ui.TextInput(c, &d.proxyPass).Password().Width(220)
				if e.Submitted() || e.PressedOutside() {
					a.applySettingsIfChanged()
				}
			})
			if ui.Button(c, "重新生成").FontSize(11).Clicked() {
				d.proxyUser = model.ProxyUsernameDefault
				d.proxyPass = model.NewProxyPassword()
				a.saveSettings()
			}
			if ui.Button(c, "复制密码").FontSize(11).Clicked() {
				a.copyText(strings.TrimSpace(d.proxyPass))
			}
		})
		ui.Text(c, "局域网访问需要认证：SOCKS5 用这组用户名/密码，HTTP 代理也要同一组；"+
			"SOCKS4 在需要认证时不可用；密码存在配置文件（仅本用户可读），不进系统凭据库。").
			FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(560)
	}
	ui.Text(c, "监听 127.0.0.1 只有本机能用，不需要密码；要让局域网里的设备用，"+
		"改成 0.0.0.0（或本机的内网地址），此时必须设置代理密码。").
		FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(560)
}

// simpleModeField 是简单模式的开关与出口。开了之后专业设置收起，
// 「显示全部设置」是唯一的回来路径，所以它就挨着开关放。
func (a *app) simpleModeField(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
		if ui.Checkbox(c, &d.simpleMode, "简单模式").Changed() {
			a.setSimpleMode(d.simpleMode)
		}
		if a.simpleMode() {
			if ui.Button(c, "显示全部设置").FontSize(11).Clicked() {
				d.simpleMode = false
				a.setSimpleMode(false)
			}
		}
	})
	ui.Text(c, "简单模式把首屏收成一张卡和一个网址输入框（接入点多于一个时仍列成清单）；"+
		"专业设置按默认值跑，要看或改它们用「显示全部设置」。").
		FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(560)
}

// appearanceFields 是颜色模式与主题配色：任何模式下都要能改。
func (a *app) appearanceFields(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	ui.Field(c, "颜色模式", func() {
		if ui.Select(c, &d.appearance, appearanceLabels()).Width(160).Changed() {
			a.applySettingsIfChanged()
		}
	})
	a.themeCards(c)
	ui.Text(c, "跟随系统时，窗口外观跟着操作系统的深浅设置变；浅色与深色会把外观固定下来。").
		FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(560)
}

// commonSwitches 是几个日常开关。「开启统一入口 SOCKS5」只在完整模式下出现：
// 简单模式唯一的代理地址就是它，关掉这一档就没意义了。
func (a *app) commonSwitches(c *ui.Context) {
	d := &a.settings
	ui.Column(c).Gap(4).Children(func() {
		if !a.simpleMode() {
			if ui.Checkbox(c, &d.aggregate, "开启统一入口 SOCKS5").Changed() {
				a.applySettingsIfChanged()
			}
		}
		if ui.Checkbox(c, &d.autoReconnect, "连接断开时自动重连").Changed() {
			a.applySettingsIfChanged()
		}
		if supportsDockToggle() {
			if ui.Checkbox(c, &d.hideDock, "关闭后隐藏 Dock 图标").Changed() {
				a.applySettingsIfChanged()
			}
		}
		// 「关闭窗口时退出程序」只在 Linux/Windows 有，并进同一个勾选区。
		a.quitOnCloseSwitch(c)
	})
	if a.quitOnCloseSupported() {
		ui.Text(c, quitOnCloseHint()).FontSize(11).TextColor(c.Theme().TextMuted).Wrap().MaxWidth(560)
	}
}

// captureSection 是「网络与接管」：接管方式是一个下拉，状态与诊断在下面。
func (a *app) captureSection(c *ui.Context) {
	settingsGroup(c, "接管方式", func() { a.captureSettings(c) })
	settingsGroup(c, "状态与日志", func() { a.captureStatusGroup(c) })
}

func (a *app) captureSettings(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	// 下拉反映真实状态；用户改选时由 applyCaptureMode 负责先关掉其他方式。
	d.mode = a.captureMode()
	d.autoRestoreAppCapture = a.cfg.Settings.AutoRestoreAppCapture
	if ui.Select(c, &d.mode, a.captureModes()).Label("选择接管方式").Width(180).Changed() {
		a.applyCaptureMode(d.mode)
	}
	description := "系统网络保持原样。登录后仍可从接入点打开代理浏览器。"
	switch a.captureMode() {
	case captureSystem:
		description = "使用系统代理设置的应用会通过代理访问网络。"
	case captureGlobalTUN:
		description = "使用 aTrust 会话接管整机 IPv4 TCP 流量。"
	case captureAppCapture:
		description = "仅接管在线接入点授权的网段和域名，公网默认路由保持原样。支持 IPv4 TCP，UDP 为试验功能。"
	}
	ui.Text(c, description).FontSize(12).TextColor(t.TextMuted).Wrap().MaxWidth(560)
	if supportsResourceTUN() {
		if ok, reason := autoCaptureSupportedFn(); ok {
			if ui.Checkbox(c, &d.autoRestoreAppCapture,
				"启动 / 登录后自动恢复应用接管").Changed() {
				if err := a.setAutoRestoreAppCapture(d.autoRestoreAppCapture); err != nil {
					// 关闭失败也会强制本次运行保持关闭；不要在界面上又勾回去。
					d.autoRestoreAppCapture = false
					a.toast = "保存自动恢复设置失败：" + err.Error()
				}
			}
			ui.Text(c, "网络助手就绪且有网关在线时自动恢复。手动切换或取消接管会关闭此选项；取消勾选只影响下次恢复。").
				FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(620)
			// 上次用的是应用接管、本次却没有自动接管：把原因写在用户看得见的地方，
			// 而不是让人对着一个「不使用」猜。
			if a.cfg.Settings.CaptureMode == model.CaptureModeApp &&
				!a.cfg.Settings.AutoRestoreAppCapture && a.captureMode() == captureOff {
				ui.Text(c, "上次使用的是「应用接管」，本次未自动接管；勾选上面的选项后，下次启动或登录时会自动接管。").
					FontSize(11).TextColor(t.Warning).Wrap().MaxWidth(620)
			}
			if line := a.autoCaptureStatusLine(); line != "" {
				color := t.TextMuted
				if a.autoCapturePaused() {
					color = t.Warning
				}
				ui.Row(c).Gap(8).AlignItems(ui.Center).Wrap().Children(func() {
					ui.Text(c, line).FontSize(11).TextColor(color).Wrap().MaxWidth(560)
					if a.autoCapturePaused() && ui.Button(c, "重试").FontSize(11).Clicked() {
						a.retryAutoCapture()
					}
				})
			}
		} else {
			ui.Text(c, "自动恢复不可用："+reason).
				FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(620)
			// 说清实际后果：没有这个开关时，重启就是会回到「不使用」。
			ui.Text(c, "重启后接管方式会回到「不使用」，需要时在下拉里重新选一次。").
				FontSize(11).TextColor(t.TextMuted).Wrap().MaxWidth(620)
		}
	}
}

func (a *app) captureStatusGroup(c *ui.Context) {
	t := c.Theme()
	ui.Row(c).Gap(10).AlignItems(ui.Center).Wrap().Children(func() {
		ui.Text(c, "当前接管："+a.captureMode()).FontSize(12).TextColor(t.TextMuted)
		if a.simpleMode() {
			return
		}
		agg := a.mgr.Aggregate()
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
	a.captureStatus(c)
}

// logsSection 是「日志」：运行日志开关与访问日志页入口。
func (a *app) logsSection(c *ui.Context) {
	t := c.Theme()
	settingsGroup(c, "运行日志", func() {
		ui.Row(c).Gap(8).Wrap().Children(func() {
			if ui.Button(c, logLabel(a.logsOpen)).FontSize(12).Clicked() {
				a.logsOpen = !a.logsOpen
			}
			if ui.Button(c, "访问日志页").FontSize(12).Clicked() {
				a.goTab(2)
			}
		})
		if a.logsOpen {
			a.logPanel(c)
		} else {
			ui.Text(c, "查看登录、断开、接管与连接失败的记录。").FontSize(12).TextColor(t.TextMuted).Wrap()
		}
	})
	settingsGroup(c, "TUN 与接管日志", func() {
		ui.Text(c, "排查应用接管和 TUN 的启动、运行或清理问题。").FontSize(12).TextColor(t.TextMuted).Wrap()
		ui.Row(c).Children(func() {
			if ui.Button(c, "打开 TUN 日志").FontSize(12).Clicked() {
				a.openTUNLog()
			}
		})
	})
}

// aboutSection 是「关于」：版本、更新、项目主页、数据目录与退出。
func (a *app) aboutSection(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	settingsGroup(c, "版本与链接", func() {
		ui.Text(c, appName+" "+appBuild).FontSize(13).TextColor(t.TextMuted).Wrap()
		ui.Column(c).Gap(4).Children(func() {
			if ui.Checkbox(c, &d.autoCheckUpdate, "自动检查更新（启动时及之后每天检查一次，发现新版本时在状态栏提示）").Changed() {
				a.applySettingsIfChanged()
			}
		})
		ui.Row(c).Gap(8).Wrap().Children(func() {
			checkLabel := "检查更新"
			if a.updateChecking.Load() {
				checkLabel = "正在检查…"
			}
			if ui.Button(c, checkLabel).FontSize(12).Clicked() {
				go a.checkForUpdate(true)
			}
			if ui.Button(c, "项目主页").FontSize(12).Clicked() {
				a.openProject()
			}
			if ui.Button(c, "打开数据目录").FontSize(12).Clicked() {
				if err := mygo.Shell.OpenPath(a.dir); err != nil {
					a.toast = "打不开数据目录：" + err.Error()
				}
			}
			if a.update != nil && ui.PrimaryButton(c, "下载 v"+a.update.Version).FontSize(12).Clicked() {
				a.openUpdate()
			}
		})
	})
	settingsGroup(c, "退出应用", func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "彻底退出程序，托盘图标也会关闭。").
				FontSize(12).TextColor(t.TextMuted).Grow(1).MinWidth(0).Wrap()
			if ui.Button(c, "退出 "+appName).FontSize(12).Shrink(0).Clicked() {
				a.quitAsk = true
			}
		})
	})
}
