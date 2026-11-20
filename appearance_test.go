package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/store"
)

// 设置页选的颜色模式要真的落盘，重开配置还是那一档。
func TestAppearanceSavedBySettingsPage(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	a.settings.appearance = "深色"
	a.saveSettings()
	if a.settings.err != "" {
		t.Fatalf("保存设置失败：%s", a.settings.err)
	}
	if got := a.cfg.Settings.Appearance; got != "dark" {
		t.Fatalf("内存里的颜色模式 = %q，想要 dark", got)
	}
	secrets, err := store.NewFileSecrets(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(a.dir, secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Config().Settings.Appearance; got != "dark" {
		t.Fatalf("落盘的颜色模式 = %q，想要 dark", got)
	}
	// 重新打开设置页应当回填深色，而不是退回默认。
	a.openSettings()
	if a.settings.appearance != "深色" {
		t.Fatalf("重开后回填 = %q", a.settings.appearance)
	}
}

// 颜色模式：三档必须真的改主题，不能只是下拉里的字。
func TestAppearanceModePicksTheme(t *testing.T) {
	a := testApp(t)
	cases := []struct {
		saved     string
		system    bool
		wantDark  bool
		wantLabel string
	}{
		{"", true, true, "跟随系统"},
		{"", false, false, "跟随系统"},
		{"system", true, true, "跟随系统"},
		{"light", true, false, "浅色"},
		{"dark", false, true, "深色"},
		{"garbage", false, false, "跟随系统"},
	}
	for _, c := range cases {
		a.cfg.Settings.Appearance = c.saved
		a.settings.open = false
		if got := a.appearanceDark(c.system); got != c.wantDark {
			t.Errorf("appearance=%q 系统深色=%v：想要 dark=%v，得到 %v", c.saved, c.system, c.wantDark, got)
		}
		if got := appearanceLabel(a.savedAppearance()); got != c.wantLabel {
			t.Errorf("appearance=%q：想要标签 %q，得到 %q", c.saved, c.wantLabel, got)
		}
		if c.wantDark {
			if a.appearanceTheme(c.system) != softDark {
				t.Errorf("appearance=%q 应当选深色主题", c.saved)
			}
		} else if a.appearanceTheme(c.system) != softLight {
			t.Errorf("appearance=%q 应当选浅色主题", c.saved)
		}
	}
}

// 浅色模式下窗口真的画成浅色：拿渲染结果的像素说话，不看文案。
func TestAppearanceLightOverridesDarkSystem(t *testing.T) {
	a := testApp(t)
	a.cfg.Settings.Appearance = "light"
	a.settings.open = false
	tt := ui.NewTester(a.view, 1120, 780)
	tt.SetDark(true) // 系统是深色，但偏好是浅色
	tt.Frame()
	img := tt.Image()
	// 取窗口左下角一块纯背景区域：浅色主题的底色比深色主题亮得多。
	sum := 0
	n := 0
	for y := img.Bounds().Max.Y - 30; y < img.Bounds().Max.Y; y++ {
		for x := 6; x < 40; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			sum += int((r + g + b) / 3 >> 8)
			n++
		}
	}
	if n == 0 {
		t.Fatal("没有取到像素")
	}
	avg := sum / n
	if avg < 128 {
		t.Fatalf("浅色模式下的背景平均亮度 = %d，看起来仍然是深色", avg)
	}
}

// 深色模式反过来也要生效（系统是浅色时把窗口压深）。
func TestAppearanceDarkOverridesLightSystem(t *testing.T) {
	a := testApp(t)
	a.cfg.Settings.Appearance = "dark"
	a.settings.open = false
	tt := ui.NewTester(a.view, 1120, 780)
	tt.SetDark(false)
	tt.Frame()
	img := tt.Image()
	sum, n := 0, 0
	for y := img.Bounds().Max.Y - 30; y < img.Bounds().Max.Y; y++ {
		for x := 6; x < 40; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			sum += int((r + g + b) / 3 >> 8)
			n++
		}
	}
	if n == 0 {
		t.Fatal("没有取到像素")
	}
	if avg := sum / n; avg >= 128 {
		t.Fatalf("深色模式下的背景平均亮度 = %d，仍然是浅色", avg)
	}
}

// 设置页「通用」里要能看到三档，并且默认选中已保存的那一档。
func TestAppearanceSettingShownInSettingsPage(t *testing.T) {
	a := testApp(t)
	a.cfg.Settings.Appearance = "dark"
	a.openSettings()
	if a.settings.appearance != "深色" {
		t.Fatalf("打开设置页时应当回填已保存的颜色模式，得到 %q", a.settings.appearance)
	}
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"颜色模式", "跟随系统", "浅色", "深色"} {
		if !strings.Contains(texts, want) {
			t.Errorf("设置页缺少 %q；texts = %s", want, texts)
		}
	}
}

// 草稿改动会即时预览，关掉设置页就回到已保存的值。
func TestAppearanceDraftPreviewOnlyWhileEditing(t *testing.T) {
	a := testApp(t)
	a.cfg.Settings.Appearance = "light"
	a.openSettings()
	a.settings.appearance = "深色"
	if !a.appearanceDark(false) {
		t.Fatal("草稿选深色时应当立即预览深色")
	}
	a.settings.open = false
	if a.appearanceDark(false) {
		t.Fatal("关掉设置页后应当回到已保存的浅色")
	}
}
