package main

import "github.com/egoist/mygo/ui"

// 接管方式是高频的运行时动作（查内网、跑 git/docker、临时走公网），
// 所以它不能藏在设置页：顶栏这颗胶囊左边是连通状态，中间是当前方式，
// 右边一个小箭头——点开就地下拉，选一项立刻生效，最后一条才进设置。

// captureChipLabel 给下拉里的一项做当前标记，顺便统一文案。
func captureChipLabel(mode string) string {
	return mode
}

// captureChip 是顶栏的「状态 + 切接管」胶囊与它的下拉。
func (a *app) captureChip(c *ui.Context) {
	t := c.Theme()
	online, _, _ := a.mgr.Counts()
	dot := t.TextMuted
	if online > 0 {
		dot = t.Success
	}
	mode := a.captureMode()
	chip := ui.Row(c).Padding(4, 10).Radius(999).Background(t.Surface).
		Border(1, t.Border).AlignItems(ui.Center).Gap(6).
		Tooltip("切换接管方式").
		OnClick(func() {
			a.captureMenuOpen = !a.captureMenuOpen
			a.invalidate()
		})
	chip.Children(func() {
		ui.Row(c).Size(6, 6).Radius(3).Background(dot)
		ui.Text(c, captureChipLabel(mode)).FontSize(11).TextColor(t.Text)
		ui.Text(c, "▾").FontSize(10).TextColor(t.TextMuted)
	})
	ui.Popover(c, chip, &a.captureMenuOpen, func() {
		panel := ui.Column(c).Width(200).Padding(5).Gap(1).Radius(12).
			Background(t.Surface).Border(1, t.Border).
			Shadow(0, 8, 24, 0, cardShadow(t))
		panel.Children(func() {
			for _, label := range captureModes() {
				option := label
				item := ui.Row(c).Padding(6, 9).Radius(8).Gap(8).AlignItems(ui.Center).
					OnClick(func() {
						a.applyCaptureMode(option)
						a.captureMenuOpen = false
						a.invalidate()
					})
				if item.Hovered() {
					item = item.Background(t.SurfaceHover)
				}
				item.Children(func() {
					if option == mode {
						ui.Text(c, "✓").FontSize(11).TextColor(t.Accent)
					} else {
						ui.Row(c).Width(11)
					}
					ui.Text(c, option).FontSize(11)
				})
			}
			ui.Divider(c)
			if ui.Button(c, "⚙ 网络与高级设置…").Label("网络与接管设置").
				FontSize(11).Clicked() {
				a.captureMenuOpen = false
				a.openSettingsAt(settingNetwork)
			}
		})
	})
}
