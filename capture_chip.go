package main

import "github.com/egoist/mygo/ui"

// 接管方式是高频的运行时动作（查内网、跑 git/docker、临时走公网），
// 所以它不能藏在设置页：顶栏这颗胶囊左边是连通状态，中间是当前方式，
// 右边一个小箭头——点开就地下拉，选一项立刻生效，最后一条才进设置。

// captureChipLabel 给下拉里的一项做当前标记，顺便统一文案。
func captureChipLabel(mode string) string {
	return mode
}

// captureSettingsEntry 是下拉最后一行：真的需要配网段/DNS 时才进设置页。
// 名字跟设置页的分区标题「网络与接管」对齐，免得两个地方叫两个名字。
const captureSettingsEntry = "网络与接管设置"

// captureChip 是顶栏的「状态 + 切接管」胶囊与它的下拉。
func (a *app) captureChip(c *ui.Context) {
	t := c.Theme()
	// 下拉里每一行都用这一个样式：选项和底部入口是同类，入口不是按钮。
	row := func(onClick func(), children func()) {
		item := ui.Row(c).Padding(6, 9).Radius(8).Gap(8).AlignItems(ui.Center).
			OnClick(onClick)
		if item.Hovered() {
			item = item.Background(t.SurfaceHover)
		}
		item.Children(children)
	}
	online, _, _ := a.mgr.Counts()
	dot := t.TextMuted
	if online > 0 {
		dot = t.Success
	}
	mode := a.captureMode()
	chip := ui.Row(c).Padding(5, 9).Radius(6).Background(t.Surface).
		Border(1, t.Border).AlignItems(ui.Center).Gap(6).
		Tooltip("切换接管方式").
		OnClick(func() {
			a.captureMenuOpen = !a.captureMenuOpen
			if a.captureMenuOpen {
				// 下拉里没出现的档位要能查到原因。
				a.logHiddenCaptureModes()
			}
			a.invalidate()
		})
	chip.Children(func() {
		ui.Row(c).Size(6, 6).Radius(3).Background(dot)
		ui.Text(c, captureChipLabel(mode)).FontSize(12).TextColor(t.Text)
		ui.Text(c, "▾").FontSize(10).TextColor(t.TextMuted)
	})
	ui.Popover(c, chip, &a.captureMenuOpen, func() {
		panel := ui.Column(c).Width(200).Padding(5).Gap(1).Radius(12).
			Background(t.Surface).Border(1, t.Border).
			Shadow(0, 8, 24, 0, cardShadow(t))
		panel.Children(func() {
			for _, label := range a.captureModes() {
				option := label
				row(func() {
					a.applyCaptureMode(option)
					a.captureMenuOpen = false
					a.invalidate()
				}, func() {
					if option == mode {
						ui.Text(c, "✓").FontSize(11).TextColor(t.Accent)
					} else {
						ui.Row(c).Width(11)
					}
					ui.Text(c, option).FontSize(11)
				})
			}
			ui.Divider(c)
			row(func() {
				a.captureMenuOpen = false
				a.openSettingsAt(settingNetwork)
			}, func() {
				// 左边留出与勾选列同宽的空位，文字才能与上面几行对齐。
				ui.Row(c).Width(11)
				ui.Text(c, captureSettingsEntry).FontSize(11)
			})
		})
	})
}
