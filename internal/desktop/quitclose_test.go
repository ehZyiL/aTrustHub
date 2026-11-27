package desktop

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
)

// 关闭动作是纯决策：平台 × 开关 × 是否有活动 × 有没有托盘。
func TestCloseActionFor(t *testing.T) {
	cases := []struct {
		name   string
		goos   string
		quit   bool
		active bool
		tray   bool
		want   closeAction
	}{
		{"Linux 有托盘：关窗藏起来，后台继续跑", "linux", false, true, true, closeHide},
		{"Linux 有托盘且无活动：也是藏起来", "linux", false, false, true, closeHide},
		{"Linux 有托盘、勾了开关且无活动：直接退出", "linux", true, false, true, closeQuit},
		{"Linux 有托盘、勾了开关但有连接：先确认", "linux", true, true, true, closeConfirm},
		{"Linux 没托盘：关窗即退出，不留后台", "linux", false, true, false, closeQuit},
		{"Linux 没托盘、勾了开关也一样退出", "linux", true, true, false, closeQuit},
		{"macOS 关窗是隐藏", "darwin", false, true, false, closeHide},
		{"macOS 开关不生效", "darwin", true, true, false, closeHide},
		{"Windows 默认隐藏到托盘", "windows", false, true, true, closeHide},
		{"Windows 勾了开关且无活动：直接退出", "windows", true, false, true, closeQuit},
		{"Windows 勾了开关但有连接：先确认", "windows", true, true, true, closeConfirm},
	}
	for _, c := range cases {
		if got := closeActionFor(c.goos, c.quit, c.active, c.tray); got != c.want {
			t.Errorf("%s：closeActionFor(%q, %v, %v, %v) = %v，想要 %v",
				c.name, c.goos, c.quit, c.active, c.tray, got, c.want)
		}
	}
}

// 开关只在平台支持、且托盘真的建起来时出现。
func TestQuitOnCloseSwitchVisibility(t *testing.T) {
	a := testApp(t)
	// 测试进程里没有面板，托盘建不起来：就不该出现「隐藏到托盘」的开关。
	a.tray = nil
	if a.quitOnCloseSupported() {
		t.Fatal("托盘不可用时 quitOnCloseSupported() 必须为 false")
	}
	a.openSettings()
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	has := strings.Contains(texts, "关闭主窗口时退出程序")
	if a.quitOnCloseSupported() != has {
		t.Fatalf("quitOnCloseSupported()=%v 但界面里出现开关=%v", a.quitOnCloseSupported(), has)
	}
	if a.quitOnCloseSupported() && !strings.Contains(texts, "关闭时只隐藏到系统托盘") {
		t.Error("开关旁边应当有行为说明")
	}
}

// 勾选即落盘，重开设置页回填。
func TestQuitOnClosePersists(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	a.settings.quitOnClose = true
	a.applySettingsIfChanged()
	if a.settings.err != "" {
		t.Fatalf("保存失败：%s", a.settings.err)
	}
	if !a.store.Config().Settings.QuitOnClose {
		t.Fatal("QuitOnClose 没有落盘")
	}
	a.openSettings()
	if !a.settings.quitOnClose {
		t.Error("重开设置页应当回填已保存的值")
	}
}

// 有在线接入点时算「有活动」，关闭要走确认。
func TestHasActiveWorkCountsOnlinePoints(t *testing.T) {
	a := layoutApp(t)
	if !a.hasActiveWork() {
		t.Error("有在线接入点时应视为有活动")
	}
	empty := testApp(t)
	if empty.hasActiveWork() {
		t.Error("什么都没有时不该视为有活动")
	}
}
