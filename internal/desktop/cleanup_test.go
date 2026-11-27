package desktop

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	cleanupclient "github.com/ehzyil/connect-hub/internal/cleanup/client"
	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

type cleanupStub struct{ calls int }

func (s *cleanupStub) Run(context.Context, contract.Request, func(cleanupclient.Snapshot)) cleanupclient.Snapshot {
	s.calls++
	return cleanupclient.Snapshot{}
}

type cleanupPageRunner struct{ requests chan contract.Request }

func (r *cleanupPageRunner) Run(_ context.Context, req contract.Request, publish func(cleanupclient.Snapshot)) cleanupclient.Snapshot {
	s := cleanupclient.Snapshot{Operation: req.Operation, Done: true, Result: contract.Result{Outcome: "complete", Total: 3, OK: 1, Skipped: 1, Reboot: 1}}
	publish(s)
	r.requests <- req
	return s
}

func TestMaintenanceConfirmationSelectionAndResult(t *testing.T) {
	a := testApp(t)
	a.settings.open, a.settings.section = true, settingMaintenance
	runner := &cleanupPageRunner{requests: make(chan contract.Request, 1)}
	a.cleanup.task = cleanupclient.NewTaskController(runner, nil)
	a.cleanup.scanDir = "fixture-scan"
	a.cleanup.selected = map[string]bool{"normal": true, "deep": false}
	a.cleanup.view.Findings = []contract.Finding{{ID: "normal", Title: "普通残留"}, {ID: "deep", Title: "深度残留", Deep: true}}
	tt := ui.NewTester(a.maintenanceSection, 1120, 1000)
	if err := tt.Click("备份并清理所选项"); err != nil {
		t.Fatal(err)
	}
	if a.cleanup.confirm != contract.Apply || a.cleanup.busy {
		t.Fatal("mutation ran before confirmation")
	}
	if err := tt.Click("返回检查"); err != nil {
		t.Fatal(err)
	}
	if a.cleanup.confirm != "" || a.cleanup.busy {
		t.Fatal("back did not cancel confirmation")
	}
	if err := tt.Click("备份并清理所选项"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("确认执行"); err != nil {
		t.Fatal(err)
	}
	select {
	case req := <-runner.requests:
		if req.Operation != contract.Apply || req.ScanDir != "fixture-scan" || len(req.Selected) != 1 || req.Selected[0] != "normal" {
			t.Fatalf("incorrect request: %+v", req)
		}
	case <-time.After(time.Second):
		t.Fatal("confirmed task not launched")
	}
	deadline := time.Now().Add(time.Second)
	for a.cleanup.busy && time.Now().Before(deadline) {
		a.drainCleanup()
		time.Sleep(time.Millisecond)
	}
	tt.Frame()
	text := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"成功 1 项", "已不存在/跳过 1 项", "重启生效 1 项"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing result %q: %s", want, text)
		}
	}
	if a.cleanup.busy || len(a.cleanup.view.Findings) > 0 || a.cleanup.scanDir != "" {
		t.Fatal("completed task retained selection")
	}
}

func TestMaintenancePageDoesNotStartOptionalWork(t *testing.T) {
	a := testApp(t)
	stub := &cleanupStub{}
	a.cleanup.task = cleanupclient.NewTaskController(stub, nil)
	a.settings.open = true
	a.settings.section = settingMaintenance
	ui.NewTester(a.maintenanceSection, 1120, 800).Texts()
	if stub.calls != 0 || a.cleanup.busy {
		t.Fatal("opening maintenance started work")
	}
	a.cleanup.view.Component = components.Snapshot{Availability: components.Missing, State: components.Failed, Detail: "清理组件不可用，基础 VPN 仍可使用"}
	texts := strings.Join(ui.NewTester(a.maintenanceSection, 1120, 800).Texts(), "|")
	if !strings.Contains(texts, "基础 VPN 仍可使用") {
		t.Fatal("missing component not represented")
	}
}

func TestCleanupPageCloseReleasesScanAndBoundedState(t *testing.T) {
	a := testApp(t)
	dir, err := taskio.NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.cleanup.scanDir = dir
	a.cleanup.selected = map[string]bool{"x": true}
	a.cleanup.view = cleanupclient.Snapshot{Findings: []contract.Finding{{ID: "x"}}, Backups: []contract.Backup{{ID: "b"}}, Logs: []string{"log"}, Installed: []string{"app"}}
	a.drainCleanup()
	if a.cleanup.scanDir != "" || a.cleanup.selected != nil || a.cleanup.view.Findings != nil || a.cleanup.view.Backups != nil || a.cleanup.view.Logs != nil || a.cleanup.view.Installed != nil {
		t.Fatal("closed page retains detailed state")
	}
	if taskio.ValidateDir(dir) == nil {
		t.Fatal("unused scan directory retained")
	}
}

func TestCleanupClosingPageCancelsOnlyReadonlyTask(t *testing.T) {
	for _, op := range []string{contract.Scan, contract.List, contract.Apply, contract.Restore} {
		a := testApp(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		entered := make(chan context.Context, 1)
		a.cleanup.task = cleanupclient.NewTaskController(cleanupBlockingRunner{entered: entered}, nil)
		a.cleanup.task.Start(ctx, contract.Request{})
		taskContext := <-entered
		a.cleanup.busy = true
		a.cleanup.view.Operation = op
		a.drainCleanup()
		readonly := op == contract.Scan || op == contract.List
		if (taskContext.Err() != nil) != readonly {
			t.Fatalf("page close cancellation for %s: %v", op, taskContext.Err())
		}
		a.shutdownCleanup()
		if taskContext.Err() == nil {
			t.Fatal("shutdown did not request safe stop")
		}
	}
}

type cleanupBlockingRunner struct{ entered chan context.Context }

func (r cleanupBlockingRunner) Run(ctx context.Context, _ contract.Request, _ func(cleanupclient.Snapshot)) cleanupclient.Snapshot {
	r.entered <- ctx
	<-ctx.Done()
	return cleanupclient.Snapshot{Done: true}
}

func TestCleanupMutationBlockedWhileNetworkActive(t *testing.T) {
	a := testApp(t)
	stub := &cleanupStub{}
	a.cleanup.task = cleanupclient.NewTaskController(stub, nil)
	a.tunOn.Store(true)
	a.startCleanup(contract.Request{Request: components.Request{Operation: contract.Restore}, BackupID: "fixture"})
	if a.cleanup.busy || stub.calls != 0 || !strings.Contains(a.cleanup.view.Component.Detail, "断开") {
		t.Fatal("cleanup allowed with active capture")
	}
}

func TestCleanupCannotStartAfterShutdownWithoutPreviousTask(t *testing.T) {
	a := testApp(t)
	a.shutdownCleanup()
	a.startCleanup(contract.Request{Request: components.Request{Operation: contract.List}})
	if a.cleanup.busy || a.cleanup.task.Drain() != nil {
		t.Fatal("shutdown allowed a previously unused cleanup task to start")
	}
}
