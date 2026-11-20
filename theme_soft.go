package main

import "github.com/egoist/mygo/ui"

// 布局原型用的是一套安静的中性配色：卡片只比窗口亮一档、描边是发丝线、
// 次要文字偏灰、强调色只有一处。框架默认主题的卡片反而比窗口更暗，
// 所以这里整份替换，同时把字号 13、圆角 10、间距 4 一并带上。
var (
	softLight = newSoftTheme(false)
	softDark  = newSoftTheme(true)
)

func newSoftTheme(dark bool) *ui.Theme {
	t := ui.LightTheme()
	if dark {
		t = ui.DarkTheme()
	}
	t.Radius = 10
	t.Spacing = 4
	t.FontSize = 13
	// 滑块比默认的 6 DIP 略宽、颜色更淡，悬停时才出现，不抢内容。
	t.ScrollbarWidth = 8
	if dark {
		t.Background = ui.Hex("#23232b")
		t.Surface = ui.Hex("#292931")
		t.SurfaceHover = ui.Hex("#2e2d38")
		t.SurfacePressed = ui.Hex("#353440")
		t.Border = ui.Hex("#3a3844")
		t.Text = ui.Hex("#e5e2ee")
		t.TextMuted = ui.Hex("#9c99a8")
		t.Accent = ui.Hex("#4f8cff")
		t.AccentHover = ui.Hex("#6a9dff")
		t.AccentPressed = ui.Hex("#3c78e0")
		t.AccentText = ui.Hex("#ffffff")
		t.Danger = ui.Hex("#d28b90")
		t.Warning = ui.Hex("#d3a860")
		t.Success = ui.Hex("#7db69c")
		t.Selection = ui.RGBA(79, 140, 255, 0.35)
		t.Focus = ui.RGBA(79, 140, 255, 0.55)
		t.Scrollbar = ui.RGBA(255, 255, 255, 0.26)
		return t
	}
	t.Background = ui.Hex("#fcfcfe")
	t.Surface = ui.Hex("#ffffff")
	t.SurfaceHover = ui.Hex("#f5f5fa")
	t.SurfacePressed = ui.Hex("#ececf3")
	t.Border = ui.Hex("#e8e8f0")
	t.Text = ui.Hex("#333440")
	t.TextMuted = ui.Hex("#686a75")
	t.Accent = ui.Hex("#2f6fe4")
	t.AccentHover = ui.Hex("#1f5ed3")
	t.AccentPressed = ui.Hex("#1b52bd")
	t.AccentText = ui.Hex("#ffffff")
	t.Danger = ui.Hex("#a5525b")
	t.Warning = ui.Hex("#a9762a")
	t.Success = ui.Hex("#3f8a6d")
	t.Selection = ui.RGBA(47, 111, 228, 0.22)
	t.Focus = ui.RGBA(47, 111, 228, 0.45)
	t.Scrollbar = ui.RGBA(0, 0, 0, 0.18)
	return t
}
