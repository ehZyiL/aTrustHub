package desktop

import (
	"context"
	"runtime"

	cleanupclient "github.com/ehzyil/connect-hub/internal/cleanup/client"
	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/components"
)

type cleanupState struct {
	task     *cleanupclient.TaskController
	view     cleanupclient.Snapshot // Below this line: UI-thread owned.
	busy     bool
	selected map[string]bool
	scanDir  string
	confirm  string
	backupID string
	visible  bool
}

func supportsCleanup() bool { return runtime.GOOS == "windows" }

func (a *app) startCleanup(request contract.Request) {
	s := &a.cleanup
	if s.busy || a.quitRequested.Load() {
		return
	}
	if (request.Operation == contract.Apply || request.Operation == contract.Restore) && a.hasActiveWork() {
		s.view.Component.Detail = "请先断开 VPN 并关闭网络接管，再执行清理或恢复"
		return
	}
	if s.task == nil {
		s.task = cleanupclient.NewTaskController(cleanupclient.New(cleanupclient.Options{DataDir: a.dir}), a.invalidateCoalesced)
	}
	if request.Operation == contract.Apply {
		request.ScanDir = s.scanDir
		for id, v := range s.selected {
			if v {
				request.Selected = append(request.Selected, id)
			}
		}
		if len(request.Selected) == 0 {
			s.view.Component.Detail = "请先选择要清理的条目"
			return
		}
	}
	if request.Operation != contract.Apply && s.scanDir != "" {
		_ = cleanupclient.Discard(s.scanDir)
		s.scanDir = ""
	}
	if !s.task.Start(context.Background(), request) {
		return
	}
	s.busy = true
	s.selected = nil
	s.view = cleanupclient.Snapshot{Operation: request.Operation, Component: components.Snapshot{Availability: components.Ready, State: components.Starting, Detail: "正在启动清理组件"}}
}

func (a *app) drainCleanup() {
	s := &a.cleanup
	var next *cleanupclient.Snapshot
	if s.task != nil {
		next = s.task.Drain()
	}
	if next != nil {
		s.view = *next
		if next.Done {
			s.busy = false
			if s.scanDir != "" {
				_ = cleanupclient.Discard(s.scanDir)
				s.scanDir = ""
			}
			if next.Operation == contract.Scan && next.Result.Outcome == "complete" {
				s.scanDir = next.TaskDir
				s.selected = make(map[string]bool, len(next.Findings))
				for _, f := range next.Findings {
					s.selected[f.ID] = f.Selected
				}
			}
		}
	}
	visible := a.settings.open && a.settings.section == settingMaintenance
	if !visible {
		if s.busy && (s.view.Operation == contract.Scan || s.view.Operation == contract.List) {
			a.cancelCleanup()
		}
		if !s.busy {
			a.releaseCleanupDetails()
		}
	}
	s.visible = visible
}

func (a *app) releaseCleanupDetails() {
	s := &a.cleanup
	s.view.Findings = nil
	s.view.Installed = nil
	s.view.Backups = nil
	s.view.Logs = nil
	s.selected = nil
	s.confirm = ""
	if s.scanDir != "" {
		_ = cleanupclient.Discard(s.scanDir)
		s.scanDir = ""
	}
}

func (a *app) cancelCleanup() {
	if a.cleanup.task != nil {
		a.cleanup.task.Cancel()
	}
}

func (a *app) shutdownCleanup() {
	s := &a.cleanup
	if s.task != nil {
		s.task.Close()
	}
	// An active component owns its directory until it exits. If Hub itself
	// crashes its lease expires and it stops at the same safe checkpoint.
	if !s.busy {
		a.releaseCleanupDetails()
	}
}
