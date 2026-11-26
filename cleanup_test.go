package main

import (
	"context"
	"strings"
	"testing"

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

func TestMaintenancePageDoesNotStartOptionalWork(t *testing.T) {
	a := testApp(t)
	stub := &cleanupStub{}
	a.cleanup.runner = stub
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
		a.cleanup.cancel = cancel
		a.cleanup.busy = true
		a.cleanup.view.Operation = op
		a.drainCleanup()
		readonly := op == contract.Scan || op == contract.List
		if (ctx.Err() != nil) != readonly {
			t.Fatalf("page close cancellation for %s: %v", op, ctx.Err())
		}
		a.shutdownCleanup()
		if ctx.Err() == nil {
			t.Fatal("shutdown did not request safe stop")
		}
	}
}

func TestCleanupMutationBlockedWhileNetworkActive(t *testing.T) {
	a := testApp(t)
	stub := &cleanupStub{}
	a.cleanup.runner = stub
	a.tunOn.Store(true)
	a.startCleanup(contract.Request{Request: components.Request{Operation: contract.Restore}, BackupID: "fixture"})
	if a.cleanup.busy || stub.calls != 0 || !strings.Contains(a.cleanup.view.Component.Detail, "断开") {
		t.Fatal("cleanup allowed with active capture")
	}
}
