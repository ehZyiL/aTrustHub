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
	tester := ui.NewTester(a.view, 1120, 800)
	if err := tester.Click("系统 TUN"); err != nil {
		t.Fatal(err)
	}
	waitController(t, a.resourceTUN, func(s resourceTUNStatus) bool { return s.Running })
	if a.tunOn || a.tunWanted {
		t.Fatal("new capture enabled legacy handoff")
	}
	tester.Frame()
	if !strings.Contains(strings.Join(tester.Texts(), "|"), "关闭系统 TUN") {
		t.Fatal("ready state missing")
	}
	if err := tester.Click("关闭系统 TUN"); err != nil {
		t.Fatal(err)
	}
	waitController(t, a.resourceTUN, func(s resourceTUNStatus) bool { return !s.Running && !s.Busy })
}
