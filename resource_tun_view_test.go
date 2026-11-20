package main

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/localapps"
	"github.com/qy/easyconnect/internal/model"
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
	for _, want := range []string{"接管方式", "应用接管：未启用", "当前接管："} {
		if !strings.Contains(texts, want) {
			t.Fatalf("设置页缺少 %q；texts = %s", want, texts)
		}
	}
	a.applyCaptureMode(captureAppCapture)
	waitController(t, a.resourceTUN, func(s resourceTUNStatus) bool { return s.Running })
	if a.tunOn || a.tunWanted {
		t.Fatal("new capture enabled legacy handoff")
	}
	tester.Frame()
	if !strings.Contains(strings.Join(tester.Texts(), "|"), "应用接管：已接管") {
		t.Fatal("ready state missing")
	}
	a.applyCaptureMode(captureOff)
	waitController(t, a.resourceTUN, func(s resourceTUNStatus) bool { return !s.Running && !s.Busy })
}
