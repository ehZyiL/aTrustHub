package desktop

import (
	"fmt"
	"github.com/egoist/mygo/ui"
)

func (a *app) describeProgress() string {
	online, connecting, total := a.mgr.Counts()
	switch {
	case total == 0:
		return "还没有接入点"
	case connecting > 0:
		return fmt.Sprintf("%d 个在线，%d 个登录中", online, connecting)
	default:
		return fmt.Sprintf("%d / %d 个在线", online, total)
	}
}

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
	// 日志回调只能读原子快照，这里在主线程算一次「日志面板是否在画」。
	a.syncLogViewActive()
	// 后台只写 Store；配置的发布点只有这里，主线程读写 a.cfg。
	a.applyPendingConfigReload()
	a.drainCleanup()
	// The firewall rule follows the share's running state; this only acts when
	// that state changed and never prompts for elevation.
	a.syncLanShareFirewallIfNeeded()
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
	// ⌘1–⌘n 跳到顶栏对应的段：简单模式下只有两段，键位跟着段走。
	for i, ref := range a.pages() {
		if i >= len(pageShortcuts) {
			break
		}
		page := ref.Tab
		root.OnShortcut(ui.Cmd, pageShortcuts[i], func() {
			a.goTab(page)
		})
	}
	root.Children(func() {
		a.toolbar(c)
		// 操作栏与内容之间一条发丝线。
		ui.Divider(c)
		if !a.settings.open {
			a.lanShareStrip(c)
		}
		a.launcherBody(c)
		if !a.settings.open {
			if !a.simpleMode() {
				a.envStrip(c)
			}
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
	a.lanShareView(c)
	a.drainLANDiscovery()
	a.relayImportView(c)
	a.relayDiagnoseView(c)
	a.relayPointView(c)
	a.relayHistoryConfirmView(c)
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
		if ui.PrimaryButton(c, "＋ 接入点").Label("＋ 添加接入点").FontSize(12).Clicked() {
			a.openNewEditor()
		}
	})
}
