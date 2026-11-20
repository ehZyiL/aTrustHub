package main

import "github.com/egoist/mygo/ui"

type platformCaptureSetup struct{}

func (a *app) captureSetupView(c *ui.Context) {
	ui.Text(c, "Windows 实验版：首次启动接管项目时，请在系统 UAC 窗口授权网络助手。主程序请使用普通权限运行；同一 VPN 下的后续软件共用助手。").FontSize(12).TextColor(c.Theme().TextMuted).Wrap()
}
func (a *app) captureSetupBusy() bool { return false }
func (a *app) closeCaptureSetup()     {}
