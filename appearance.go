package main

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

// appearanceTheme 按当前偏好在柔和主题里挑一份。
func (a *app) appearanceTheme(systemDark bool) *ui.Theme {
	if a.appearanceDark(systemDark) {
		return softDark
	}
	return softLight
}
