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
	t.Radius = 14
	t.Spacing = 4
	t.FontSize = 13
	if dark {
		t.Background = ui.Hex("#141b1a")
		t.Surface = ui.Hex("#1c2523")
		t.SurfaceHover = ui.Hex("#202b28")
		t.SurfacePressed = ui.Hex("#29352f")
		t.Border = ui.Hex("#32403a")
		t.Text = ui.Hex("#e7eee9")
		t.TextMuted = ui.Hex("#94a49b")
		t.Accent = ui.Hex("#c4e7a0")
		t.AccentHover = ui.Hex("#d5f0b8")
		t.AccentPressed = ui.Hex("#aed586")
		t.AccentText = ui.Hex("#16241c")
		t.Danger = ui.Hex("#e8a695")
		t.Warning = ui.Hex("#dfba73")
		t.Success = ui.Hex("#a4d6aa")
		t.Selection = ui.Hex("#2d3f33")
		t.Focus = ui.RGBA(196, 231, 160, 0.40)
		t.Scrollbar = ui.RGBA(255, 255, 255, 0.22)
		return t
	}
	t.Background = ui.Hex("#f4f7f5")
	t.Surface = ui.Hex("#ffffff")
	t.SurfaceHover = ui.Hex("#f6f9f7")
	t.SurfacePressed = ui.Hex("#e9f0eb")
	t.Border = ui.Hex("#e2eae4")
	t.Text = ui.Hex("#1d2b25")
	t.TextMuted = ui.Hex("#6f7d76")
	t.Accent = ui.Hex("#2f6b4f")
	t.AccentHover = ui.Hex("#275a43")
	t.AccentPressed = ui.Hex("#1f4a37")
	t.AccentText = ui.Hex("#ffffff")
	t.Danger = ui.Hex("#b1594a")
	t.Warning = ui.Hex("#9b7126")
	t.Success = ui.Hex("#2f7c58")
	t.Selection = ui.Hex("#e6f0e9")
	t.Focus = ui.RGBA(47, 107, 79, 0.28)
	t.Scrollbar = ui.RGBA(0, 0, 0, 0.14)
	return t
}

// cardShadow 是卡片与面板的“呼吸阴影”：比边框更轻，抬起半像素而不抢内容。
func cardShadow(t *ui.Theme) ui.Color {
	if t.Dark {
		return ui.RGBA(0, 0, 0, 0.50)
	}
	return ui.RGBA(31, 74, 55, 0.07)
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
