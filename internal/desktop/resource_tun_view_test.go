package desktop

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/model"
)

func TestSystemTUNControlVisibleForEasyConnectAndSeparateFromLegacy(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows system capture UI")
	}
	a := testApp(t)
	a.cfg.Points = []model.AccessPoint{{ID: "B", Name: "B", Protocol: model.ProtocolEasyConnect}}
	r := &controllerRuntime{done: make(chan struct{})}
	a.resourceTUN = &resourceTUNController{configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, start: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) { return r, nil }, suspendProxy: func() (func() error, error) { return func() error { return nil }, nil }}
	t.Cleanup(func() { a.resourceTUN.Close() })
	// 接管开关从顶栏搬进了设置页的「网络与接管」：先确认控件在，再驱动状态机。
	a.openSettingsAt(settingNetwork)
	tester := ui.NewTester(a.view, 1120, 800)
	texts := strings.Join(tester.Texts(), "|")
	for _, want := range []string{"接管方式", "应用接管：未启用", "没有在线接入点", "当前接管："} {
		if !strings.Contains(texts, want) {
			t.Fatalf("设置页缺少 %q；texts = %s", want, texts)
		}
	}
	// 没有在线网关时切换会被拒绝：不拆当前模式，也不能打开旧 TUN 移交。
	a.applyCaptureMode(captureAppCapture)
	if a.tunOn.Load() || a.tunWanted.Load() {
		t.Fatal("new capture enabled legacy handoff")
	}
	if !strings.Contains(a.toast, "没有在线接入点") {
		t.Fatalf("无在线网关时应当说明原因，实际 toast=%q", a.toast)
	}
	if a.resourceTUN.View().Running {
		t.Fatal("被拒绝的切换不应启动接管")
	}
	// 直接驱动控制器验证「已接管」状态与设置页文案。
	a.resourceTUN.Start()
	waitController(t, a.resourceTUN, func(s resourceTUNStatus) bool { return s.Running })
	tester.Frame()
	if !strings.Contains(strings.Join(tester.Texts(), "|"), "应用接管：已接管") {
		t.Fatal("ready state missing")
	}
	a.applyCaptureMode(captureOff)
	waitController(t, a.resourceTUN, func(s resourceTUNStatus) bool { return !s.Running && !s.Busy })
}
