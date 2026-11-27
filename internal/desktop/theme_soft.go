package desktop

import "github.com/egoist/mygo/ui"

// 配色分成两个正交维度：外观模式（跟随系统 / 浅色 / 深色）与主题色系
// （经典蓝白 / 极客森绿 / 柔和紫灰）。每套色系各带浅色与深色两版，
// 组合在启动时一次建好，运行时只换指针，不重建主题。
//
// 布局参数（圆角 14、间距 4、字号 13）与色系无关，三套一致。

const (
	themeBlue   = "blue"
	themeGreen  = "green"
	themePurple = "purple"
)

// themeNames 是设置页里卡片顺序。
func themeNames() []string {
	return []string{themeBlue, themeGreen, themePurple}
}

// themeLabel 是卡片标题。
func themeLabel(name string) string {
	switch name {
	case themeGreen:
		return "极客森绿"
	case themePurple:
		return "柔和紫灰"
	default:
		return "经典蓝白"
	}
}

// themeBlurb 是卡片副标题：一句话说清适合谁。
func themeBlurb(name string) string {
	switch name {
	case themeGreen:
		return "护眼终端感，暗光下更稳"
	case themePurple:
		return "现代中性，边界最轻"
	default:
		return "官方蓝白，沉稳权威"
	}
}

// palette 是一套色系在某个明暗下的全部用色。
type palette struct {
	background, surface, surfaceHover, surfacePressed ui.Color
	border, text, textMuted                           ui.Color
	accent, accentHover, accentPressed, accentText    ui.Color
	danger, warning, success, selection               ui.Color
	scrollbar                                         ui.Color
}

// palettes 返回色系 name 在指定明暗下的用色。
func palettes(name string, dark bool) palette {
	switch name {
	case themeGreen:
		if dark {
			return palette{
				background:     ui.Hex("#141b1a"),
				surface:        ui.Hex("#1b2422"),
				surfaceHover:   ui.Hex("#1f2724"),
				surfacePressed: ui.Hex("#283230"),
				border:         ui.Hex("#2f3b35"),
				text:           ui.Hex("#e7eee9"),
				textMuted:      ui.Hex("#8f9d95"),
				// 荧光绿只给「在线、选中、主按钮」：强调色不稀释。
				accent:        ui.Hex("#c4e7a0"),
				accentHover:   ui.Hex("#d3efb4"),
				accentPressed: ui.Hex("#b2dc86"),
				accentText:    ui.Hex("#16241c"),
				danger:        ui.Hex("#e8a695"),
				warning:       ui.Hex("#dfba73"),
				success:       ui.Hex("#a4d6aa"),
				selection:     ui.Hex("#243029"),
				scrollbar:     ui.RGBA(255, 255, 255, 0.20),
			}
		}
		return palette{
			background:     ui.Hex("#f4f7f5"),
			surface:        ui.Hex("#ffffff"),
			surfaceHover:   ui.Hex("#f6f9f7"),
			surfacePressed: ui.Hex("#e9f0eb"),
			border:         ui.Hex("#e2eae4"),
			text:           ui.Hex("#1d2b25"),
			textMuted:      ui.Hex("#6f7d76"),
			accent:         ui.Hex("#2f6b4f"),
			accentHover:    ui.Hex("#275a43"),
			accentPressed:  ui.Hex("#1f4a37"),
			accentText:     ui.Hex("#ffffff"),
			danger:         ui.Hex("#b1594a"),
			warning:        ui.Hex("#9b7126"),
			success:        ui.Hex("#2f7c58"),
			selection:      ui.Hex("#e6f0e9"),
			scrollbar:      ui.RGBA(0, 0, 0, 0.14),
		}
	case themePurple:
		if dark {
			return palette{
				background:     ui.Hex("#23232b"),
				surface:        ui.Hex("#292931"),
				surfaceHover:   ui.Hex("#2e2d38"),
				surfacePressed: ui.Hex("#353440"),
				border:         ui.Hex("#3a3844"),
				text:           ui.Hex("#e5e2ee"),
				textMuted:      ui.Hex("#9c99a8"),
				accent:         ui.Hex("#b0a0ef"),
				accentHover:    ui.Hex("#c4b7f5"),
				accentPressed:  ui.Hex("#9c8ae6"),
				accentText:     ui.Hex("#1b1a22"),
				danger:         ui.Hex("#d28b90"),
				warning:        ui.Hex("#d3a860"),
				success:        ui.Hex("#7db69c"),
				selection:      ui.Hex("#332e46"),
				scrollbar:      ui.RGBA(255, 255, 255, 0.26),
			}
		}
		return palette{
			background:     ui.Hex("#fcfcfe"),
			surface:        ui.Hex("#ffffff"),
			surfaceHover:   ui.Hex("#f5f5fa"),
			surfacePressed: ui.Hex("#ececf3"),
			border:         ui.Hex("#e8e8f0"),
			text:           ui.Hex("#333440"),
			textMuted:      ui.Hex("#686a75"),
			accent:         ui.Hex("#7864da"),
			accentHover:    ui.Hex("#684fd1"),
			accentPressed:  ui.Hex("#5b45c0"),
			accentText:     ui.Hex("#ffffff"),
			danger:         ui.Hex("#a5525b"),
			warning:        ui.Hex("#a9762a"),
			success:        ui.Hex("#3f8a6d"),
			selection:      ui.Hex("#e8e2fa"),
			scrollbar:      ui.RGBA(0, 0, 0, 0.16),
		}
	default: // themeBlue
		if dark {
			return palette{
				background:     ui.Hex("#0f172a"),
				surface:        ui.Hex("#18223c"),
				surfaceHover:   ui.Hex("#1e2a46"),
				surfacePressed: ui.Hex("#26334f"),
				border:         ui.Hex("#2b3a56"),
				text:           ui.Hex("#e2e8f0"),
				textMuted:      ui.Hex("#94a3b8"),
				accent:         ui.Hex("#60a5fa"),
				accentHover:    ui.Hex("#82b8fb"),
				accentPressed:  ui.Hex("#4a92ef"),
				accentText:     ui.Hex("#0b1220"),
				danger:         ui.Hex("#f0a1a8"),
				warning:        ui.Hex("#e6c07b"),
				success:        ui.Hex("#7dd3a8"),
				selection:      ui.Hex("#1e2b4a"),
				scrollbar:      ui.RGBA(255, 255, 255, 0.22),
			}
		}
		return palette{
			background:     ui.Hex("#f6f8fc"),
			surface:        ui.Hex("#ffffff"),
			surfaceHover:   ui.Hex("#f1f5fb"),
			surfacePressed: ui.Hex("#e4ebf7"),
			border:         ui.Hex("#e2e8f2"),
			text:           ui.Hex("#1e293b"),
			textMuted:      ui.Hex("#64748b"),
			accent:         ui.Hex("#2563eb"),
			accentHover:    ui.Hex("#1d4fd7"),
			accentPressed:  ui.Hex("#1a44b8"),
			accentText:     ui.Hex("#ffffff"),
			danger:         ui.Hex("#b6455b"),
			warning:        ui.Hex("#a8730f"),
			success:        ui.Hex("#2f7d5d"),
			selection:      ui.Hex("#e8efff"),
			scrollbar:      ui.RGBA(0, 0, 0, 0.15),
		}
	}
}

// newAppTheme 把一套用色装进 ui.Theme：布局参数三套统一。
func newAppTheme(name string, dark bool) *ui.Theme {
	t := ui.LightTheme()
	if dark {
		t = ui.DarkTheme()
	}
	p := palettes(name, dark)
	t.Radius = 14
	t.Spacing = 4
	t.FontSize = 13
	t.Background = p.background
	t.Surface = p.surface
	t.SurfaceHover = p.surfaceHover
	t.SurfacePressed = p.surfacePressed
	t.Border = p.border
	t.Text = p.text
	t.TextMuted = p.textMuted
	t.Accent = p.accent
	t.AccentHover = p.accentHover
	t.AccentPressed = p.accentPressed
	t.AccentText = p.accentText
	t.Danger = p.danger
	t.Warning = p.warning
	t.Success = p.success
	t.Selection = p.selection
	t.Scrollbar = p.scrollbar
	t.Focus = p.accent.Alpha(0.32)
	return t
}

// themeKey 是三套 × 深浅六个实例的键。
func themeKey(name string, dark bool) string {
	if dark {
		return name + "-dark"
	}
	return name + "-light"
}

// appThemeRegistry 在启动时一次建好，运行时只换指针。
var appThemeRegistry = func() map[string]*ui.Theme {
	out := make(map[string]*ui.Theme, 6)
	for _, name := range themeNames() {
		for _, dark := range []bool{false, true} {
			out[themeKey(name, dark)] = newAppTheme(name, dark)
		}
	}
	return out
}()

// appTheme 取某色系某明暗的主题；未知色系按默认（经典蓝白）处理。
func appTheme(name string, dark bool) *ui.Theme {
	if t, ok := appThemeRegistry[themeKey(name, dark)]; ok {
		return t
	}
	return appThemeRegistry[themeKey(themeBlue, dark)]
}

// 旧名字保留：默认色系（经典蓝白）的深浅两版，测试与老调用点都在用。
var (
	softLight = appTheme(themeBlue, false)
	softDark  = appTheme(themeBlue, true)
)

// cardShadow 是卡片与面板的「呼吸阴影」：比边框更轻，抬起半像素而不抢内容。
func cardShadow(t *ui.Theme) ui.Color {
	if t.Dark {
		return ui.RGBA(0, 0, 0, 0.45)
	}
	return ui.RGBA(20, 33, 61, 0.07)
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
	glyphs := glyphPalette(t)
	if name == "" {
		return glyphs[0]
	}
	h := 0
	for _, r := range name {
		h = (h*31 + int(r)) & 0x7fffffff
	}
	return glyphs[h%len(glyphs)]
}
