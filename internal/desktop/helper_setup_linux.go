package desktop

import (
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/capture"
	"github.com/ehzyil/connect-hub/internal/model"
)

type platformCaptureSetup struct{ controller *capture.HelperSetup }

func (a *app) captureSetupView(c *ui.Context) {
	if a.captureUI.controller == nil {
		a.captureUI.controller = capture.NewHelperSetup(func() {
			a.invalidateCoalesced()
		})
		a.captureUI.controller.Check()
	}
	controller := a.captureUI.controller
	state := controller.Snapshot()
	t := c.Theme()
	ui.Column(c).Padding(14).Gap(6).Radius(12).Border(1, t.Border).Background(t.Surface).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Text(c, "Linux 软件接管助手").Bold().FontSize(13).Grow(1)
			if ui.Button(c, "检查状态").Disabled(state.Busy).Clicked() {
				controller.Check()
			}
			label := "安装 / 更新辅助服务"
			if state.Ready {
				label = "更新辅助服务"
			}
			if ui.PrimaryButton(c, label).Disabled(state.Busy).Clicked() {
				a.installCaptureHelper()
			}
		})
		color := t.TextMuted
		if state.Checked && !state.Ready && !state.Busy {
			color = t.Warning
		}
		ui.Text(c, state.Message).TextColor(color).FontSize(13).Wrap()
		if !state.Ready || state.Installing {
			ui.Text(c, "首次安装需要系统认证，密码只在系统窗口输入。安装时请保持此窗口打开。").FontSize(11).TextColor(t.TextMuted).Wrap()
		}
	})
}

func (a *app) installCaptureHelper() {
	if !captureExperimentEnabled() || a.captureUI.controller == nil {
		return
	}
	a.localLife.Lock()
	defer a.localLife.Unlock()
	if a.local != nil {
		for _, v := range a.local.Views() {
			if v.Mode == model.LocalAppCapture && localProjectBusy(v) {
				a.toast = "请先停止正在运行或准备中的软件接管项目，再更新辅助服务"
				return
			}
		}
	}
	a.captureUI.controller.Install()
}

func (a *app) captureSetupBusy() bool {
	return a.captureUI.controller != nil && a.captureUI.controller.Snapshot().Installing
}

func (a *app) closeCaptureSetup() {
	if a.captureUI.controller != nil {
		a.captureUI.controller.Close()
	}
}
