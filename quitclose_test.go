package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
)

// 关闭动作是纯决策：平台 × 开关 × 是否有活动。
func TestCloseActionFor(t *testing.T) {
	cases := []struct {
		name   string
		goos   string
		quit   bool
		active bool
		want   closeAction
	}{
		{"Linux 关窗即退出（无开关）", "linux", false, true, closeQuit},
		{"Linux 关窗即退出（开关也不影响）", "linux", true, false, closeQuit},
		{"macOS 关窗是隐藏", "darwin", false, true, closeHide},
		{"macOS 开关不生效", "darwin", true, true, closeHide},
		{"Windows 默认隐藏到托盘", "windows", false, true, closeHide},
		{"Windows 勾了开关且无活动：直接退出", "windows", true, false, closeQuit},
		{"Windows 勾了开关但有连接：先确认", "windows", true, true, closeConfirm},
	}
	for _, c := range cases {
		if got := closeActionFor(c.goos, c.quit, c.active); got != c.want {
			t.Errorf("%s：closeActionFor(%q, %v, %v) = %v，想要 %v",
				c.name, c.goos, c.quit, c.active, got, c.want)
		}
	}
}

// 开关只在 Windows 出现，且并进通用面板的勾选区。
func TestQuitOnCloseSwitchVisibility(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	has := strings.Contains(texts, "关闭主窗口时退出程序")
	if supportsQuitOnClose() != has {
		t.Fatalf("supportsQuitOnClose()=%v 但界面里出现开关=%v", supportsQuitOnClose(), has)
	}
	if supportsQuitOnClose() && !strings.Contains(texts, "关闭时只隐藏到系统托盘") {
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
