package desktop

import "github.com/egoist/mygo/ui"

// 颜色模式：默认跟随系统，另外两档把窗口外观钉住。持久化在
// Settings.Appearance 里（"system" / "light" / "dark"），设置页打开时
// 用草稿值即时预览，取消就回落成已保存的值。

const (
	appearanceSystem = "system"
	appearanceLight  = "light"
	appearanceDark   = "dark"
)

// appearanceLabels 是设置页下拉的三档，顺序与 Select 选项一致。
func appearanceLabels() []string {
	return []string{"跟随系统", "浅色", "深色"}
}

// appearanceLabel 把配置值翻成下拉里显示的文案。
func appearanceLabel(pref string) string {
	switch pref {
	case appearanceLight:
		return "浅色"
	case appearanceDark:
		return "深色"
	default:
		return "跟随系统"
	}
}

// appearanceFromLabel 把下拉文案翻回配置值；未知文案按跟随系统处理。
func appearanceFromLabel(label string) string {
	switch label {
	case "浅色":
		return appearanceLight
	case "深色":
		return appearanceDark
	default:
		return appearanceSystem
	}
}

// savedAppearance 是配置里存的偏好，空值或异常值都按跟随系统处理。
func (a *app) savedAppearance() string {
	switch a.cfg.Settings.Appearance {
	case appearanceLight:
		return appearanceLight
	case appearanceDark:
		return appearanceDark
	default:
		return appearanceSystem
	}
}

// appearancePref 是这一帧生效的偏好：设置页打开时先按草稿画，便于即时预览。
func (a *app) appearancePref() string {
	if a.settings.open && a.settings.appearance != "" {
		return appearanceFromLabel(a.settings.appearance)
	}
	return a.savedAppearance()
}

// appearanceDark 决定这一帧用深色还是浅色主题：跟随系统时听系统的。
func (a *app) appearanceDark(systemDark bool) bool {
	switch a.appearancePref() {
	case appearanceLight:
		return false
	case appearanceDark:
		return true
	default:
		return systemDark
	}
}

// savedTheme 是配置里存的色系，空值或异常值都按默认（经典蓝白）处理。
func (a *app) savedTheme() string {
	switch a.cfg.Settings.Theme {
	case themeGreen, themePurple:
		return a.cfg.Settings.Theme
	default:
		return themeBlue
	}
}

// themePref 是这一帧生效的色系：设置页打开时先按草稿画，便于即时预览。
func (a *app) themePref() string {
	if a.settings.open {
		switch a.settings.theme {
		case themeGreen, themePurple, themeBlue:
			return a.settings.theme
		}
	}
	return a.savedTheme()
}

// appearanceTheme 按「外观模式 × 色系」挑一份预建好的主题。
func (a *app) appearanceTheme(systemDark bool) *ui.Theme {
	return appTheme(a.themePref(), a.appearanceDark(systemDark))
}

// themeCards 是三张色系预览卡：点哪张当场换色，也算一次设置改动。
func (a *app) themeCards(c *ui.Context) {
	t := c.Theme()
	d := &a.settings
	ui.Text(c, "主题配色").FontSize(11).TextColor(t.TextMuted)
	ui.Row(c).Gap(8).Wrap().Children(func() {
		for _, name := range themeNames() {
			option := name
			active := d.theme == option
			card := ui.Column(c).Width(186).Padding(10, 12).Radius(12).Gap(4).
				Background(t.Surface).Border(1, t.Border).
				OnClick(func() {
					d.theme = option
					a.applySettingsIfChanged()
					a.invalidate()
				})
			if active {
				card = card.Border(2, t.Accent)
			}
			card.Children(func() {
				ui.Row(c).Gap(6).AlignItems(ui.Center).Children(func() {
					// 小圆点用该色系自己的强调色，卡片本身就是预览。
					ui.Row(c).Size(9, 9).Radius(5).
						Background(appTheme(option, t.Dark).Accent)
					ui.Text(c, themeLabel(option)).FontSize(12).Bold()
					ui.Row(c).Grow(1)
					if active {
						ui.Text(c, "✓").FontSize(11).TextColor(t.Accent)
					}
				})
				ui.Text(c, themeBlurb(option)).FontSize(10).TextColor(t.TextMuted).Wrap()
			})
		}
	})
}
