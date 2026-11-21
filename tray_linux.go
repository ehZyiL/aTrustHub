//go:build linux && !android

package main

import (
	"github.com/egoist/mygo"
)

// setupTray adds the notification-area icon, so closing the window keeps the
// app (and its tunnels) running. On Linux the icon is a StatusNotifierItem
// through libayatana-appindicator3, which mygo loads at run time.
//
// GNOME 默认没有最小化按钮（button-layout 只有 close），所以托盘是关窗之后
// 唯一能回到窗口的路：没有托盘就不许藏窗口，见 closeActionFor。
func (a *app) setupTray() {
	if a.tray != nil {
		return
	}
	icon := loadAppIconPNG()
	if len(icon) == 0 {
		a.tunLogf("托盘不可用：没有找到 icon.png，关窗将直接退出")
		return
	}
	tray, err := mygo.NewTray(mygo.TrayOptions{
		ID:   "main",
		Icon: icon,
		// 不要设 Title：Linux 后端把 Title 变成 app_indicator_set_label，
		// 面板会在图标旁边画一排字。悬停提示走 ToolTip（set_title）。
		ToolTip: appName,
		Menu: mygo.NewMenu([]*mygo.MenuItem{
			{Label: "显示窗口", Click: func(*mygo.MenuItem, *mygo.Window) { a.showWindow() }},
			mygo.Separator(),
			{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { a.quitFromTray() }},
		}),
	})
	if err != nil {
		// 没有 libayatana-appindicator3，或面板没有 StatusNotifierWatcher
		// （GNOME 需要 AppIndicator 扩展）：藏起来就再也叫不回来。
		a.tunLogf("托盘不可用：%v；关窗将直接退出", err)
		return
	}
	tray.OnClick(a.showWindow)
	a.tray = tray
}

// supportsDockToggle reports whether the Dock icon can be hidden here.
func supportsDockToggle() bool { return false }

// startupTray puts the icon in the panel from the start, so the user sees the
// app is still running after the window is hidden.
func (a *app) startupTray() { a.setupTray() }

// updateDockVisibility does nothing on Linux, which has no Dock.
func (a *app) updateDockVisibility(hidden bool) {}
