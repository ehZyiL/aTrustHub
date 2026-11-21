package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// 首次运行（以及旧配置里没有这个字段）默认是系统代理；用户显式关掉要留住。
func TestSettingsCaptureModeDefault(t *testing.T) {
	s := model.DefaultSettings()
	if s.CaptureMode != model.CaptureModeSystem {
		t.Fatalf("首次运行的接管方式应为系统代理，实际 %q", s.CaptureMode)
	}
	s.CaptureMode = model.CaptureModeOff
	s.Normalize()
	if s.CaptureMode != model.CaptureModeOff {
		t.Errorf("用户关掉接管后不该被重置：%q", s.CaptureMode)
	}
	s.CaptureMode = "乱写"
	s.Normalize()
	if s.CaptureMode != model.CaptureModeSystem {
		t.Errorf("脏值应归到默认的系统代理：%q", s.CaptureMode)
	}
}

// 界面档位和持久化的 id 必须一一对应：id 是存盘用的，不能写界面文案。
func TestCaptureModeID(t *testing.T) {
	cases := map[string]string{
		captureOff:        model.CaptureModeOff,
		captureSystem:     model.CaptureModeSystem,
		captureGlobalTUN:  model.CaptureModeTUN,
		captureAppCapture: model.CaptureModeApp,
	}
	for label, id := range cases {
		if got := captureModeID(label); got != id {
			t.Errorf("captureModeID(%q) = %q, want %q", label, got, id)
		}
	}
}

// 默认接管：没人占着系统代理时打开它，并记住状态。
func TestEnableSystemProxyByDefault(t *testing.T) {
	a := testApp(t)
	origApply, origForeign := applySystemProxyFn, systemProxyForeignFn
	t.Cleanup(func() { applySystemProxyFn, systemProxyForeignFn = origApply, origForeign })
	systemProxyForeignFn = func(string) bool { return false }
	var applied []string
	applySystemProxyFn = func(addr string, on bool) error {
		if !on {
			t.Errorf("默认接管只应该开启，不应写入关闭：%s", addr)
		}
		applied = append(applied, addr)
		return nil
	}
	const target = "127.0.0.1:1080"
	a.enableSystemProxyByDefault(target)
	if len(applied) != 1 || applied[0] != target {
		t.Fatalf("应当写入一次「指向统一入口并开启」，实际 %v", applied)
	}
	if !a.sysProxyOn {
		t.Fatal("开启后应当记住系统代理由本应用负责")
	}
}

// 别的程序已经设了系统代理时不抢：全机只有一份设置，抢过来等于替用户改分流。
func TestEnableSystemProxyByDefaultKeepsForeignProxy(t *testing.T) {
	a := testApp(t)
	origApply, origForeign := applySystemProxyFn, systemProxyForeignFn
	t.Cleanup(func() { applySystemProxyFn, systemProxyForeignFn = origApply, origForeign })
	systemProxyForeignFn = func(string) bool { return true }
	calls := 0
	applySystemProxyFn = func(string, bool) error { calls++; return nil }

	a.enableSystemProxyByDefault("127.0.0.1:1080")
	if calls != 0 {
		t.Fatalf("第三方代理在用时不该写系统代理，实际写了 %d 次", calls)
	}
	if a.sysProxyOn {
		t.Fatal("没写成功就不能记成已接管")
	}
	if logged := tailLog(a.bus.Tail(5)); !strings.Contains(logged, "未自动开启") {
		t.Errorf("应当记一条原因日志，实际 %q", logged)
	}
}

// 写入失败要说清楚，不能谎报已开启。
func TestEnableSystemProxyByDefaultReportsFailure(t *testing.T) {
	a := testApp(t)
	origApply, origForeign := applySystemProxyFn, systemProxyForeignFn
	t.Cleanup(func() { applySystemProxyFn, systemProxyForeignFn = origApply, origForeign })
	systemProxyForeignFn = func(string) bool { return false }
	applySystemProxyFn = func(string, bool) error { return errors.New("注册表拒绝写入") }

	a.enableSystemProxyByDefault("127.0.0.1:1080")
	if a.sysProxyOn {
		t.Fatal("写入失败时不能记成已接管")
	}
	if logged := tailLog(a.bus.Tail(5)); !strings.Contains(logged, "自动开启系统代理失败") {
		t.Errorf("应当记一条失败原因，实际 %q", logged)
	}
}

// 记住的是「不使用」就不碰系统设置，并且只处理一次，不每轮重试。
func TestMaybeRestoreCaptureModeRespectsOff(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.CaptureMode = model.CaptureModeOff
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	origApply := applySystemProxyFn
	t.Cleanup(func() { applySystemProxyFn = origApply })
	calls := 0
	applySystemProxyFn = func(string, bool) error { calls++; return nil }

	a.maybeRestoreCaptureMode()
	if calls != 0 {
		t.Fatalf("接管方式是「不使用」时不该写系统代理，实际写了 %d 次", calls)
	}
	if !a.captureRestored {
		t.Error("处理过就应当标记，避免每轮 tick 重复尝试")
	}
}

// 接管方式要落盘；切到系统代理时还得把旧的 TUN 恢复开关清掉，
// 否则重启后 TUN 会抢在系统代理前面复活。
func TestPersistCaptureMode(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.TunEnabled = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	if err := a.persistCaptureMode(captureSystem); err != nil {
		t.Fatal(err)
	}
	settings := a.store.Config().Settings
	if settings.CaptureMode != model.CaptureModeSystem {
		t.Errorf("落盘的 captureMode = %q", settings.CaptureMode)
	}
	if settings.TunEnabled {
		t.Error("切到系统代理后不该再保留 TUN 的恢复开关")
	}
	if a.cfg.Settings.CaptureMode != model.CaptureModeSystem {
		t.Errorf("内存里的配置也应更新，实际 %q", a.cfg.Settings.CaptureMode)
	}
}

// 入口死掉时代理会自动关掉，但那是本应用的决定，不是用户放弃接管：标记要
// 复位，入口回来后还能自动接管回来。
func TestGuardSystemProxyAllowsLaterRestore(t *testing.T) {
	a := testApp(t)
	origApply, origOwned := applySystemProxyFn, systemProxyOwnedFn
	t.Cleanup(func() { applySystemProxyFn, systemProxyOwnedFn = origApply, origOwned })
	// 仍然是我们写的那个入口（否则会被当成别人接管，不会自动关）。
	systemProxyOwnedFn = func(string) bool { return true }
	closes := 0
	applySystemProxyFn = func(_ string, on bool) error {
		if !on {
			closes++
		}
		return nil
	}
	a.sysProxyOn = true
	a.captureRestored = true

	a.guardSystemProxy()

	if a.sysProxyOn {
		t.Fatal("入口没在监听时应当关掉系统代理")
	}
	if closes != 1 {
		t.Fatalf("应当写一次关闭，实际写了 %d 次", closes)
	}
	if a.captureRestored {
		t.Error("自动关闭后应当允许之后重新接管")
	}
}

// 选中「全局 TUN」时就记下意图（不等启动成功）：TUN 自己有限流重试。
func TestRememberTunIntent(t *testing.T) {
	a := testApp(t)
	a.quitRequested = true
	a.rememberTunIntent("A")
	if a.store.Config().Settings.TunEnabled {
		t.Error("退出过程不该记 TUN 意图")
	}
	a.quitRequested = false
	a.rememberTunIntent("A")
	s := a.store.Config().Settings
	if !s.TunEnabled || s.TunPointID != "A" {
		t.Errorf("选中 TUN 应当立刻记下意图，实际 %+v", s)
	}
	// 切换到其他档位并生效时要清掉，否则重启后 TUN 会抢回来。
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.CaptureMode = model.CaptureModeOff
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.rememberCaptureMode(captureSystem)
	if a.store.Config().Settings.TunEnabled {
		t.Error("切到系统代理后不该再保留 TUN 意图")
	}
}

// 记着 TUN 意图时，启动恢复要让路：别让系统代理抢在 TUN 的限流重试前面。
func TestMaybeRestoreCaptureModeYieldsToTunIntent(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Settings.CaptureMode = model.CaptureModeSystem
		cfg.Settings.TunEnabled = true
		cfg.Settings.TunPointID = "A"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	origApply := applySystemProxyFn
	t.Cleanup(func() { applySystemProxyFn = origApply })
	calls := 0
	applySystemProxyFn = func(string, bool) error { calls++; return nil }

	a.maybeRestoreCaptureMode()

	if calls != 0 {
		t.Fatalf("有 TUN 意图时不该抢着开系统代理，实际写了 %d 次", calls)
	}
	if a.captureRestored {
		t.Error("TUN 意图还在时不该标记已处理（TUN 放弃后还要能再判断）")
	}
}

func tailLog(entries []vpn.LogEntry) string {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, entry.Line)
	}
	return strings.Join(lines, "|")
}
