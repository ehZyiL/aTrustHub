package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
)

// 接管方式是高频切换：点胶囊应当就地展开下拉，而不是跳去设置页。
func TestCaptureChipOpensMenuInPlace(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{captureOff, captureSystem, captureGlobalTUN, "⚙ 网络与高级设置…"} {
		if !strings.Contains(texts, want) {
			t.Errorf("下拉里缺少 %q；texts = %s", want, texts)
		}
	}
	if a.settings.open {
		t.Error("点胶囊不该跳到设置页")
	}
	if !a.captureMenuOpen {
		t.Error("点胶囊后下拉应当是展开的")
	}
}

// 在下拉里选一项：菜单收起、页面不动、也不会打开设置页。
func TestCaptureChipPicksModeWithoutLeavingPage(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	if err := tt.Click(captureGlobalTUN); err != nil {
		t.Fatalf("点下拉里的 %q 失败: %v", captureGlobalTUN, err)
	}
	tt.Frame()
	if a.captureMenuOpen {
		t.Error("选完一项后下拉应当收起")
	}
	if a.settings.open {
		t.Error("就地切换不该进设置页")
	}
	if a.tab != 0 {
		t.Errorf("就地切换不该换页，tab = %d", a.tab)
	}
	// 没有在线接入点时开 TUN 只会给一句提示，不会真的改系统设置。
	if !strings.Contains(a.describeProgress(), "还没有") && a.toast == "" && a.tunOn {
		t.Errorf("预期没有在线接入点时的提示，实际 tunOn=%v toast=%q", a.tunOn, a.toast)
	}
}

// 下拉在窄窗口里也不能跑出窗口：靠右的胶囊 + 200px 面板最容易撞边。
func TestCaptureMenuFitsNarrowWindow(t *testing.T) {
	a := testApp(t)
	a.captureMenuOpen = true
	for _, size := range []struct{ w, h int }{{880, 560}, {1120, 780}} {
		tt := ui.NewTester(a.view, size.w, size.h)
		tt.Frame()
		for _, label := range []string{captureOff, captureSystem, captureGlobalTUN, "⚙ 网络与高级设置…"} {
			r, ok := tt.Find(label)
			if !ok {
				t.Errorf("%dx%d 找不到 %q", size.w, size.h, label)
				continue
			}
			if r.X < -0.5 || r.Y < -0.5 || r.X+r.W > float32(size.w)+0.5 || r.Y+r.H > float32(size.h)+0.5 {
				t.Errorf("%dx%d 的 %q 越出窗口 rect=%+v", size.w, size.h, label, r)
			}
		}
	}
}

// 下拉最后一条是深链接：真的需要配 TUN 网段/DNS 时才进设置页。
func TestCaptureChipDeepLinkGoesToNetworkSettings(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	if err := tt.Click("⚙ 网络与高级设置…"); err != nil {
		t.Fatalf("点深链接失败: %v", err)
	}
	tt.Frame()
	if !a.settings.open {
		t.Fatal("深链接应当打开设置页")
	}
	if a.settings.section != settingNetwork {
		t.Errorf("深链接应当落在「网络与接管」，实际 section = %d", a.settings.section)
	}
	if a.captureMenuOpen {
		t.Error("进设置页后下拉应当收起")
	}
}
