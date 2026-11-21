package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
)

// withATrustPoint 给测试配置加一个 aTrust 接入点：旧全局 TUN 只认 aTrust 会话。
func withATrustPoint(a *app) {
	a.cfg.Points = []model.AccessPoint{{ID: "A", Name: "A", Protocol: model.ProtocolATrust}}
}

// 接管方式是高频切换：点胶囊应当就地展开下拉，而不是跳去设置页。
func TestCaptureChipOpensMenuInPlace(t *testing.T) {
	a := testApp(t)
	withATrustPoint(a)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	visible := a.captureModes()
	// 有 aTrust 接入点就意味着全局 TUN 属于支持范围：即使还没登录也要列出来，
	// 让用户点下去得到「还差什么」的提示，而不是默默少一项。
	if supportsElevatedTUN() && !slices.Contains(visible, captureGlobalTUN) {
		t.Fatalf("有 aTrust 接入点时全局 TUN 应当列在下拉里：%v", visible)
	}
	for _, want := range append(slices.Clone(visible), captureSettingsEntry) {
		if !strings.Contains(texts, want) {
			t.Errorf("下拉里缺少 %q；texts = %s", want, texts)
		}
	}
	// 不可用的档位直接隐藏，而不是列出来给人点。
	for _, mode := range allCaptureModes {
		if slices.Contains(visible, mode) {
			continue
		}
		if strings.Contains(texts, mode) {
			t.Errorf("不可用的 %q 不该出现在下拉里；texts = %s", mode, texts)
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
	withATrustPoint(a)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	// 只点「还开不了」的档位：真正能生效的档位会写系统代理或起 TUN，测试里不碰。
	pick := ""
	for _, mode := range a.captureModes() {
		if mode == a.captureMode() {
			continue
		}
		if reason := a.captureBlocker(mode); reason != "" {
			pick = mode
			break
		}
	}
	if pick == "" {
		t.Skip("当前环境下没有可验证提示的档位")
	}
	if err := tt.Click(pick); err != nil {
		t.Fatalf("点下拉里的 %q 失败: %v", pick, err)
	}
	tt.Frame()
	// view() 把 toast 交给框架后会清空字段；拒绝原因同时写进运行日志。
	if !strings.Contains(tailLog(a.bus.Tail(10)), "未生效") {
		t.Errorf("点 %q 被拒绝时应当给出原因；log = %s", pick, tailLog(a.bus.Tail(10)))
	}
	if a.captureMenuOpen {
		t.Error("选完一项后下拉应当收起")
	}
	if a.settings.open {
		t.Error("就地切换不该进设置页")
	}
	if a.tab != 0 {
		t.Errorf("就地切换不该换页，tab = %d", a.tab)
	}
	// 提示是转瞬即逝的（下一帧就被 view() 消费掉），可查的是运行日志。
	found := ""
	for _, entry := range a.bus.Tail(50) {
		if strings.Contains(entry.Line, "未生效") && strings.Contains(entry.Line, pick) {
			found = entry.Line
		}
	}
	if found == "" {
		t.Errorf("点 %q 被拒绝时应当把原因写进运行日志；日志 = %+v", pick, a.bus.Tail(50))
	}
}

// 没登录时「全局 TUN」仍然列在下拉里，点它要说明缺什么、且不动当前模式。
func TestCaptureMenuPromptsForUnreadyMode(t *testing.T) {
	if !supportsElevatedTUN() {
		t.Skip("当前平台没有全局 TUN 档位")
	}
	a := testApp(t)
	withATrustPoint(a)
	if !slices.Contains(a.captureModes(), captureGlobalTUN) {
		t.Fatalf("有 aTrust 接入点时全局 TUN 应当列出：%v", a.captureModes())
	}
	if reason := a.captureBlocker(captureGlobalTUN); !strings.Contains(reason, "aTrust") {
		t.Fatalf("提示应当说明缺 aTrust 会话，实际 %q", reason)
	}
	a.applyCaptureMode(captureGlobalTUN)
	if a.tunOn || a.tunWanted {
		t.Fatalf("前置不足时不该进入 TUN 状态，tunOn=%v tunWanted=%v", a.tunOn, a.tunWanted)
	}
	if !strings.Contains(a.toast, "aTrust") {
		t.Errorf("预期提示缺少在线 aTrust 接入点，实际 toast=%q", a.toast)
	}
}

// 下拉在窄窗口里也不能跑出窗口：靠右的胶囊 + 200px 面板最容易撞边。
func TestCaptureMenuFitsNarrowWindow(t *testing.T) {
	a := testApp(t)
	withATrustPoint(a)
	a.captureMenuOpen = true
	for _, size := range []struct{ w, h int }{{880, 560}, {1120, 780}} {
		tt := ui.NewTester(a.view, size.w, size.h)
		tt.Frame()
		for _, label := range append(slices.Clone(a.captureModes()), captureSettingsEntry) {
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

// 下拉最后一条和上面的选项同一套样式，但进的是设置页「网络与接管」。
func TestCaptureChipDeepLinkGoesToNetworkSettings(t *testing.T) {
	a := testApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	if err := tt.Click(captureSettingsEntry); err != nil {
		t.Fatalf("点设置入口失败: %v", err)
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

// 隐藏一项不能等于「悄悄少了个选项」：原因必须能在运行日志里查到。
func TestHiddenCaptureModesAreLogged(t *testing.T) {
	a := testApp(t)
	// 只有 EasyConnect 接入点：全局 TUN 用不了（旧组件只认 aTrust 会话）。
	a.cfg.Points = []model.AccessPoint{{ID: "B", Name: "B", Protocol: model.ProtocolEasyConnect}}
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click(captureOff); err != nil {
		t.Fatalf("点接管胶囊失败: %v", err)
	}
	tt.Frame()
	if slices.Contains(a.captureModes(), captureGlobalTUN) {
		t.Fatalf("只有 EasyConnect 接入点时全局 TUN 不该出现：%v", a.captureModes())
	}
	// 应用接管属于支持范围：即使此刻没登录也要列着，点它才提示还差什么。
	if supportsResourceTUN() && !slices.Contains(a.captureModes(), captureAppCapture) {
		t.Fatalf("应用接管应当列出（EasyConnect 的透明接管就靠它）：%v", a.captureModes())
	}
	found := ""
	for _, entry := range a.bus.Tail(20) {
		if strings.Contains(entry.Line, "接管方式里被隐藏") && strings.Contains(entry.Line, captureGlobalTUN) {
			found = entry.Line
		}
	}
	if found == "" {
		t.Fatalf("隐藏原因没有写进运行日志；日志 = %+v", a.bus.Tail(20))
	}
}

// 目标档位开不了的时候，正在生效的接管必须原样留着：先拆再开会让一次失败的
// 选择把能用的接管弄丢；而且不能把没生效的档位记进设置。
func TestCaptureRefusalKeepsCurrentMode(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.CaptureMode = model.CaptureModeOff
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.sysProxyOn = true
	if got := a.captureMode(); got != captureSystem {
		t.Fatalf("初始接管方式应当为 %q，实际 %q", captureSystem, got)
	}
	// 没有在线接入点：应用接管开不了。
	a.applyCaptureMode(captureAppCapture)
	if !a.sysProxyOn {
		t.Fatal("切换失败不该把系统代理关掉")
	}
	if got := a.captureMode(); got != captureSystem {
		t.Errorf("切换失败后接管方式应当仍为 %q，实际 %q", captureSystem, got)
	}
	if a.toast == "" {
		t.Error("切换失败应当给出原因")
	}
	if got := a.store.Config().Settings.CaptureMode; got != model.CaptureModeOff {
		t.Errorf("没切过去的档位不该写进设置，实际 %q", got)
	}
}

// 系统代理切不过去时必须报告「没动手」，调用方这才能把接管方式降回「不使用」。
func TestToggleSystemProxyReportsRefusal(t *testing.T) {
	a := testApp(t)
	// 统一入口没监听。
	if a.toggleSystemProxy() {
		t.Fatal("统一入口没监听时不该发起写入")
	}
	// 旧 TUN 还在接管。
	a.tunOn = true
	if a.toggleSystemProxy() {
		t.Fatal("全局 TUN 还在接管时不该发起写入")
	}
}

// 只记住真的生效的档位；退出过程一律不写（退出本来就会关代理、停 TUN）。
func TestRememberCaptureMode(t *testing.T) {
	a := testApp(t)
	defaultMode := a.store.Config().Settings.CaptureMode
	if defaultMode != model.CaptureModeSystem {
		t.Fatalf("默认接管方式应为系统代理，实际 %q", defaultMode)
	}
	a.quitRequested = true
	a.rememberCaptureMode(captureAppCapture)
	if got := a.store.Config().Settings.CaptureMode; got != defaultMode {
		t.Errorf("退出过程不该改记住的接管方式，实际 %q", got)
	}
	a.quitRequested = false
	a.rememberCaptureMode(captureAppCapture)
	if got := a.store.Config().Settings.CaptureMode; got != model.CaptureModeApp {
		t.Errorf("生效的档位应当落盘，实际 %q", got)
	}
}
