package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/store"
)

// 三套色系 × 深浅两版都要真的不同：强调色、底色、选中底色逐一对上预期。
func TestThemeRegistryCoversThreePalettes(t *testing.T) {
	want := map[string]struct{ light, dark string }{
		themeBlue:   {"#2563eb", "#60a5fa"},
		themeGreen:  {"#2f6b4f", "#c4e7a0"},
		themePurple: {"#7864da", "#b0a0ef"},
	}
	seen := map[ui.Color]bool{}
	for name, accents := range want {
		light := appTheme(name, false)
		dark := appTheme(name, true)
		if got := light.Accent; got != ui.Hex(accents.light) {
			t.Errorf("%s 浅色强调色 = %v，想要 %s", name, got, accents.light)
		}
		if got := dark.Accent; got != ui.Hex(accents.dark) {
			t.Errorf("%s 深色强调色 = %v，想要 %s", name, got, accents.dark)
		}
		if light.Dark || !dark.Dark {
			t.Errorf("%s 的深浅标记不对：light.Dark=%v dark.Dark=%v", name, light.Dark, dark.Dark)
		}
		// 布局参数与色系无关，三套必须一致。
		if light.Radius != 14 || dark.Radius != 14 || light.Spacing != 4 || light.FontSize != 13 {
			t.Errorf("%s 的布局参数漂了：radius=%v spacing=%v font=%v",
				name, light.Radius, light.Spacing, light.FontSize)
		}
		for _, t2 := range []*ui.Theme{light, dark} {
			if seen[t2.Background] {
				t.Errorf("%s 的底色与另一套重复：%v", name, t2.Background)
			}
			seen[t2.Background] = true
		}
		if light.Background == dark.Background {
			t.Errorf("%s 的深浅两版底色相同", name)
		}
	}
	// 未知色系退回默认，不 panic。
	if got := appTheme("chartreuse", true); got != appTheme(themeBlue, true) {
		t.Error("未知色系应当退回默认色系")
	}
}

// 默认色系是经典蓝白；配置里的脏值也按默认处理。
func TestSavedThemeDefaultsToBlue(t *testing.T) {
	a := testApp(t)
	for _, raw := range []string{"", "system", "chartreuse"} {
		a.cfg.Settings.Theme = raw
		if got := a.savedTheme(); got != themeBlue {
			t.Errorf("Theme=%q 时 savedTheme = %q，想要 %q", raw, got, themeBlue)
		}
	}
	for _, raw := range []string{themeGreen, themePurple} {
		a.cfg.Settings.Theme = raw
		if got := a.savedTheme(); got != raw {
			t.Errorf("Theme=%q 时 savedTheme = %q", raw, got)
		}
	}
}

// 设置页「通用」里要有三张色系卡，默认选中经典蓝白。
func TestThemeCardsShownInSettings(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"主题配色", "经典蓝白", "极客森绿", "柔和紫灰", "官方蓝白，沉稳权威"} {
		if !strings.Contains(texts, want) {
			t.Errorf("设置页缺少 %q；texts = %s", want, texts)
		}
	}
	if a.settings.theme != themeBlue {
		t.Errorf("打开设置页应当选中默认色系，实际 %q", a.settings.theme)
	}
}

// 点卡片就地换色：窗口主题立刻变，配置同时落盘，设置页不关。
func TestThemeCardSwitchesLive(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click("极客森绿"); err != nil {
		t.Fatalf("点色系卡失败: %v", err)
	}
	tt.Frame()
	if a.settings.theme != themeGreen {
		t.Fatalf("草稿色系 = %q，想要 green", a.settings.theme)
	}
	if got := a.appearanceTheme(false); got != appTheme(themeGreen, false) {
		t.Error("点卡片后应当立刻用绿色系渲染")
	}
	if !a.settings.open {
		t.Error("换色系不该关掉设置页")
	}
	secrets, err := store.NewFileSecrets(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(a.dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Config().Settings.Theme; got != themeGreen {
		t.Errorf("落盘的色系 = %q，想要 green", got)
	}
}

// 色系与外观模式互不干扰：绿色系也能固定在深色下。
func TestThemeCombinesWithAppearance(t *testing.T) {
	a := testApp(t)
	a.cfg.Settings.Theme = themeGreen
	a.cfg.Settings.Appearance = appearanceDark
	if got := a.appearanceTheme(false); got != appTheme(themeGreen, true) {
		t.Error("深色偏好下绿色系应当取深色版")
	}
	a.cfg.Settings.Appearance = appearanceLight
	if got := a.appearanceTheme(true); got != appTheme(themeGreen, false) {
		t.Error("浅色偏好下绿色系应当取浅色版，即使系统是深色")
	}
	a.cfg.Settings.Appearance = appearanceSystem
	if got := a.appearanceTheme(true); got != appTheme(themeGreen, true) {
		t.Error("跟随系统时应当听系统的")
	}
}
