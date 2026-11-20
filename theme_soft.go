package main

import "github.com/egoist/mygo/ui"

// 布局原型用的是一套安静的中性配色：卡片只比窗口亮一档、描边是发丝线、
// 次要文字偏灰、强调色只有一处。框架默认主题的卡片反而比窗口更暗，
// 所以这里整份替换，同时把字号 13、圆角 10、间距 4 一并带上。
//
// v2-soft 取的是参考实现（Clipnest）的色板：柔和紫作为唯一强调色，
// 选中状态用淡紫底而不是描边，围栏线（line）压到几乎看不见。
var (
	softLight = newSoftTheme(false)
	softDark  = newSoftTheme(true)
)

// textOnFill 是彩色实底上的文字：危险按钮这类“实心块”才用它。
var textOnFill = ui.RGBA(255, 255, 255, 1)

func newSoftTheme(dark bool) *ui.Theme {
	t := ui.LightTheme()
	if dark {
		t = ui.DarkTheme()
	}
	t.Radius = 10
	t.Spacing = 4
	t.FontSize = 13
	if dark {
		t.Background = ui.Hex("#23232b")
		t.Surface = ui.Hex("#292931")
		t.SurfaceHover = ui.Hex("#2e2d38")
		t.SurfacePressed = ui.Hex("#353440")
		t.Border = ui.Hex("#3a3844")
		t.Text = ui.Hex("#e5e2ee")
		t.TextMuted = ui.Hex("#9c99a8")
		t.Accent = ui.Hex("#b0a0ef")
		t.AccentHover = ui.Hex("#c4b7f5")
		t.AccentPressed = ui.Hex("#9c8ae6")
		t.AccentText = ui.Hex("#1b1a22")
		t.Danger = ui.Hex("#d28b90")
		t.Warning = ui.Hex("#d3a860")
		t.Success = ui.Hex("#7db69c")
		t.Selection = ui.Hex("#3d3654")
		t.Focus = ui.RGBA(176, 160, 239, 0.45)
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
	t.Accent = ui.Hex("#7864da")
	t.AccentHover = ui.Hex("#684fd1")
	t.AccentPressed = ui.Hex("#5b45c0")
	t.AccentText = ui.Hex("#ffffff")
	t.Danger = ui.Hex("#a5525b")
	t.Warning = ui.Hex("#a9762a")
	t.Success = ui.Hex("#3f8a6d")
	t.Selection = ui.Hex("#e8e2fa")
	t.Focus = ui.RGBA(120, 100, 218, 0.28)
	t.Scrollbar = ui.RGBA(0, 0, 0, 0.16)
	return t
}

// cardShadow 是卡片与面板的“呼吸阴影”：比边框更轻，抬起半像素而不抢内容。
func cardShadow(t *ui.Theme) ui.Color {
	if t.Dark {
		return ui.RGBA(0, 0, 0, 0.45)
	}
	return ui.RGBA(35, 26, 68, 0.07)
}

// glyphPalette 是资源色块里字母的颜色：只从主题色里挑，深色主题下同样柔和。
func glyphPalette(t *ui.Theme) []ui.Color {
	return []ui.Color{
		t.Accent,
		t.Success,
		t.Warning,
		t.Accent.Mix(t.Success, 0.45),
		t.Accent.Mix(t.Warning, 0.45),
	}
}

// glyphColor 按名称散列挑一个字母颜色，同一名称始终同色。
func glyphColor(t *ui.Theme, name string) ui.Color {
	palette := glyphPalette(t)
	if name == "" {
		return palette[0]
	}
	h := 0
	for _, r := range name {
		h = (h*31 + int(r)) & 0x7fffffff
	}
	return palette[h%len(palette)]
}
