package main

import "github.com/egoist/mygo/ui"

// 「关闭窗口」这件事在三套习惯里不一样，这里把决策提成纯函数，
// 免得平台分支散落在窗口回调里：
//   - Linux：藏进系统托盘（和 Windows 一样，后台继续跑）；只有真的没
//     托盘——缺 libayatana-appindicator3，或面板没有 StatusNotifierWatcher
//     ——才退回「关闭即退出」，免得留下找不到界面的进程；
//   - macOS：关闭即隐藏，Dock 图标还在（平台习惯）；
//   - Windows：默认隐藏到托盘，用户勾了「关闭主窗口时退出程序」才退出；
//     此时若还有在线连接 / TUN / 系统代理 / 运行中的本机项目，先确认一次。
type closeAction int

const (
	// closeHide 隐藏到托盘。
	closeHide closeAction = iota
	// closeQuit 直接退出。
	closeQuit
	// closeConfirm 先弹退出确认。
	closeConfirm
)

// closeActionFor 是纯决策：给平台、设置、是否有活动、有没有托盘就能得出动作。
func closeActionFor(goos string, quitOnClose, hasActive, trayOK bool) closeAction {
	switch goos {
	case "linux":
		if !trayOK {
			// 没有回收入口：关窗就是退出，不留后台。
			return closeQuit
		}
		if !quitOnClose {
			return closeHide
		}
		if hasActive {
			return closeConfirm
		}
		return closeQuit
	case "windows":
		if !quitOnClose {
			return closeHide
		}
		if hasActive {
			return closeConfirm
		}
		return closeQuit
	default:
		// macOS 及其它平台：关窗是隐藏，退出走菜单 / Cmd+Q。
		return closeHide
	}
}

// supportsQuitOnClose 决定这个设置项在平台上是否说得通。
func supportsQuitOnClose() bool {
	return supportsQuitOnClosePlatform()
}

// quitOnCloseSupported 还要求真的能藏进托盘：Linux 上没有托盘就只能退出，
// 此时不该给用户一个说着「隐藏到托盘」的开关。
func (a *app) quitOnCloseSupported() bool {
	return supportsQuitOnClose() && a.tray != nil
}

// quitOnCloseHint 是设置项下面的那句说明。
func quitOnCloseHint() string {
	return "开启后，点窗口关闭按钮会退出程序（有连接时先确认）；关闭时只隐藏到系统托盘，后台继续运行。"
}

// hasActiveWork 判断当前是否还有「关掉会断网」的活。
func (a *app) hasActiveWork() bool {
	if a.mgr != nil {
		if online, _, _ := a.mgr.Counts(); online > 0 {
			return true
		}
	}
	if a.tunOn || a.sysProxyOn || a.resourceTUNActive() {
		return true
	}
	for _, p := range a.cfg.LocalApps {
		if a.localView(p.ID).Running {
			return true
		}
	}
	return false
}

// quitOnCloseSwitch 把开关并进通用面板现有的勾选区。
func (a *app) quitOnCloseSwitch(c *ui.Context) {
	if !a.quitOnCloseSupported() {
		return
	}
	d := &a.settings
	if ui.Checkbox(c, &d.quitOnClose, "关闭主窗口时退出程序").Changed() {
		a.applySettingsIfChanged()
	}
}
