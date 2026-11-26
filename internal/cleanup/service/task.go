package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

type Emit func(string, contract.Update) error
type TaskHandler func(context.Context, string, contract.Request, Emit) (contract.Result, error)

// ServeTask serves exactly one operation then exits. It never terminates an
// in-progress mutation on cancellation: the handler owns its safe checkpoints.
func ServeTask(dir string, handle TaskHandler) error {
	if err := taskio.ValidateDir(dir); err != nil {
		return err
	}
	id, err := components.NewID()
	if err != nil {
		return err
	}
	hello := components.Hello{Version: components.Version, InstanceID: id, Capabilities: []string{contract.Capability}}
	if err = taskio.Write(dir, "hello.json", hello); err != nil {
		return err
	}
	var req contract.Request
	deadline := time.Now().Add(components.DefaultTimeout)
	for {
		err = taskio.Read(dir, "request.json", &req)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("等待清理请求超时")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err = req.Check(time.Now()); err != nil {
		return err
	}
	if req.InstanceID != id {
		return errors.New("清理实例不匹配")
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	var mu sync.Mutex
	var seq uint64
	var written int
	write := func(state components.State, final bool, detail string, update contract.Update) error {
		mu.Lock()
		defer mu.Unlock()
		payload, err := json.Marshal(update)
		if err != nil {
			return err
		}
		seq++
		e := components.Event{Version: components.Version, InstanceID: id, RequestID: req.RequestID, Sequence: seq, State: state, Final: final, Detail: contract.Text(detail), Payload: payload}
		if err = e.Check(); err != nil {
			return err
		}
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		// Reserve room for the final outcome even if progress exhausts its budget.
		if written+len(b) > contract.MaxStreamBytes-components.MaxMessageBytes && !final {
			return errors.New("任务报告达到上限")
		}
		if _, err = f.Write(append(b, '\n')); err != nil {
			return err
		}
		written += len(b) + 1
		return f.Sync()
	}
	ctx, cancel := context.WithDeadline(context.Background(), req.Deadline)
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		lastLease := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var stop components.Request
				if taskio.Read(dir, "cancel.json", &stop) == nil && stop.Version == components.Version && stop.InstanceID == id && stop.RequestID == req.RequestID && stop.Operation == "cancel" {
					cancel()
					return
				}
				if info, err := os.Stat(filepath.Join(dir, "lease")); err == nil && info.ModTime().After(lastLease) {
					lastLease = info.ModTime()
				}
				if time.Since(lastLease) > contract.LeaseTimeout {
					cancel()
					return
				}
			}
		}
	}()
	if err = write(components.Running, false, "清理任务已启动", contract.Update{}); err != nil {
		return err
	}
	result, runErr := handle(ctx, dir, req, func(detail string, u contract.Update) error { return write(components.Running, false, detail, u) })
	state := components.Disabled
	detail := "任务完成"
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			result.Outcome = "canceled"
			detail = "任务已在安全检查点取消，已完成操作与备份记录保留"
		} else {
			result.Outcome = "failed"
			state = components.Failed
			detail = runErr.Error()
		}
	} else if result.Outcome == "" {
		result.Outcome = "complete"
	}
	if err = write(state, true, detail, contract.Update{Result: &result}); err != nil {
		return err
	}
	return nil // Business errors are in the final event; nonzero exit means transport failure.
}

func HandleTask(ctx context.Context, dir string, req contract.Request, emit Emit) (contract.Result, error) {
	if req.Operation == contract.Apply || req.Operation == contract.Restore {
		if !filepath.IsAbs(req.BackupRoot) {
			return contract.Result{}, errors.New("备份目录必须是绝对路径")
		}
		unlock, err := lockMutations(req.BackupRoot)
		if err != nil {
			return contract.Result{}, err
		}
		defer unlock()
	}
	switch req.Operation {
	case contract.Scan:
		plan, err := Scan(ScanOptions{Context: ctx})
		if err != nil {
			return contract.Result{}, err
		}
		if err = SavePlanToFile(filepath.Join(dir, "plan.json"), plan); err != nil {
			return contract.Result{}, err
		}
		for _, warning := range plan.Warnings {
			if err = emit(warning, contract.Update{}); err != nil {
				return contract.Result{}, err
			}
		}
		for i, app := range plan.Installed {
			if i >= 32 {
				break
			}
			if err = emit("建议先通过 Windows 已安装的应用卸载官方客户端", contract.Update{Installed: contract.Text(app.Name)}); err != nil {
				return contract.Result{}, err
			}
		}
		for i, f := range plan.Findings {
			if i >= contract.MaxFindings {
				break
			}
			if err = ctx.Err(); err != nil {
				return contract.Result{}, err
			}
			if len(f.ID) > 4096 {
				return contract.Result{}, errors.New("扫描项标识过长")
			}
			u := contract.Finding{ID: f.ID, Group: contract.Text(f.Group), Title: contract.Text(f.Title), Detail: contract.Text(f.Detail), Deep: f.Risk == RiskDeep, Selected: f.Selected}
			if err = emit("", contract.Update{Finding: &u}); err != nil {
				return contract.Result{}, err
			}
		}
		return contract.Result{Total: len(plan.Findings), Truncated: len(plan.Findings) > contract.MaxFindings}, nil
	case contract.List:
		if err := reportInterruptedTasks(ctx, dir, emit); err != nil {
			return contract.Result{}, err
		}
		return listBackupSummaries(ctx, req.BackupRoot, emit)
	case contract.Apply:
		if !IsElevated() {
			return contract.Result{}, errors.New("清理需要管理员授权")
		}
		if err := taskio.ValidateDir(req.ScanDir); err != nil {
			return contract.Result{}, err
		}
		f, err := os.Open(filepath.Join(req.ScanDir, "plan.json"))
		if err != nil {
			return contract.Result{}, err
		}
		plan, err := ReadPlanFromReader(f)
		f.Close()
		if err != nil {
			return contract.Result{}, err
		}
		// Only IDs selected from the scan are accepted; never trust commands or
		// parameters supplied by the desktop or a stale plan when elevated.
		fresh, err := Scan(ScanOptions{Context: ctx})
		if err != nil {
			return contract.Result{}, err
		}
		selected, err := selectCurrentFindings(plan, fresh, req.Selected)
		if err != nil {
			return contract.Result{}, err
		}
		result := contract.Result{}
		code, err := Apply(ApplyOptions{Plan: selected, Context: ctx, BackupRootDir: req.BackupRoot, ReportPath: filepath.Join(dir, "journal.jsonl"), OnEvent: reportEmitter(emit, &result)})
		if code == 1 && err == nil {
			err = errors.New("部分清理项执行失败，请查看执行记录")
		}
		return result, err
	case contract.Restore:
		if !IsElevated() {
			return contract.Result{}, errors.New("恢复需要管理员授权")
		}
		result := contract.Result{}
		rw, err := NewReportWriter(filepath.Join(dir, "journal.jsonl"))
		if err != nil {
			return result, err
		}
		defer rw.Close()
		rw.onEvent = reportEmitter(emit, &result)
		err = RestoreBackupContext(ctx, filepath.Join(req.BackupRoot, req.BackupID, "manifest.json"), rw)
		return result, err
	default:
		return contract.Result{}, errors.New("未知清理操作")
	}
}

func reportEmitter(emit Emit, result *contract.Result) func(ReportEvent) error {
	return func(e ReportEvent) error {
		if e.BackupID != "" {
			result.BackupID = e.BackupID
		}
		if e.Event == "item" {
			switch e.Status {
			case StatusOk:
				result.OK++
			case StatusFailed:
				result.Failed++
			case StatusSkipped:
				result.Skipped++
			case StatusReboot:
				result.Reboot++
			}
		}
		if e.Event == "start" {
			result.Total = e.Total
		}
		return emit(e.Message, contract.Update{})
	}
}

func selectCurrentFindings(old, fresh *Plan, ids []string) (*Plan, error) {
	previous := map[string]Finding{}
	current := map[string]Finding{}
	for _, f := range old.Findings {
		previous[f.ID] = f
	}
	for _, f := range fresh.Findings {
		current[f.ID] = f
	}
	selected := *fresh
	selected.Findings = nil
	seen := map[string]bool{}
	for _, id := range ids {
		a, ok := previous[id]
		b, present := current[id]
		if !ok || !present || seen[id] {
			return nil, fmt.Errorf("清理项已变化或重复，请重新扫描: %s", contract.Text(id))
		}
		x, _ := json.Marshal(a.Params)
		y, _ := json.Marshal(b.Params)
		if a.Action != b.Action || string(x) != string(y) {
			return nil, fmt.Errorf("清理项参数已变化，请重新扫描: %s", contract.Text(id))
		}
		seen[id] = true
		b.Selected = true
		selected.Findings = append(selected.Findings, b)
	}
	return &selected, nil
}

func listBackupSummaries(ctx context.Context, root string, emit Emit) (contract.Result, error) {
	if root == "" {
		root = DefaultBackupRootDir()
	}
	d, err := os.Open(root)
	if os.IsNotExist(err) {
		return contract.Result{}, nil
	}
	if err != nil {
		return contract.Result{}, err
	}
	defer d.Close()
	result := contract.Result{}
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		entries, readErr := d.ReadDir(32)
		for _, e := range entries {
			if !e.IsDir() || !components.ValidID(e.Name()) {
				continue
			}
			var m BackupManifest
			if err = readManifest(filepath.Join(root, e.Name(), "manifest.json"), &m); err != nil {
				continue
			}
			result.Total++
			if result.Total > contract.MaxBackups {
				result.Truncated = true
				return result, nil
			}
			b := contract.Backup{ID: e.Name(), CreatedAt: m.CreatedAt, Files: len(m.Files), Registry: len(m.Registry), Certificates: len(m.Certificates), Policies: len(m.Policies)}
			if err = emit("", contract.Update{Backup: &b}); err != nil {
				return result, err
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return result, nil
			}
			return result, readErr
		}
	}
}
