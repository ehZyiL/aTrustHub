// Package client runs cleanup tasks without linking the cleanup service into Hub.
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

type Process interface {
	Wait() error
	Kill() error
}
type Launcher func(string, []string, bool) (Process, error)
type Options struct {
	Executable string
	DataDir    string
	Launch     Launcher // Test seam. Production uses a hidden process or UAC.
	Probe      func(context.Context, string) error
}
type Client struct{ options Options }

func New(o Options) *Client { return &Client{options: o} }

type Snapshot struct {
	Component components.Snapshot
	RequestID string
	Operation string
	TaskDir   string
	Findings  []contract.Finding
	Installed []string
	Backups   []contract.Backup
	Logs      []string
	Result    contract.Result
	Done      bool
}

func (s Snapshot) Clone() Snapshot {
	s.Findings = append([]contract.Finding(nil), s.Findings...)
	s.Installed = append([]string(nil), s.Installed...)
	s.Backups = append([]contract.Backup(nil), s.Backups...)
	s.Logs = append([]string(nil), s.Logs...)
	return s
}

func FindExecutable() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	for _, p := range []string{filepath.Join(filepath.Dir(exe), "core", "connect-hub-cleanup.exe"), filepath.Join(filepath.Dir(exe), "connect-hub-cleanup.exe")} {
		if i, err := os.Stat(p); err == nil && i.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

// Run owns and joins the one task process. Cancellation is a mailbox request,
// not CommandContext's hard kill. Read-only tasks may be killed after a grace
// period; apply/restore always finish their current recoverable checkpoint.
func (c *Client) Run(ctx context.Context, request contract.Request, publish func(Snapshot)) Snapshot {
	s := Snapshot{Operation: request.Operation, Component: components.Snapshot{Availability: components.Ready, State: components.Starting}}
	changed := true
	push := func() {
		if publish != nil {
			publish(s.Clone())
		}
		changed = false
	}
	fail := func(err error) Snapshot {
		s.Component.State = components.Failed
		s.Component.Detail = contract.Text(err.Error())
		s.Result.Outcome = "failed"
		s.Done = true
		s.Findings = nil
		s.Installed = nil
		s.Backups = nil
		push()
		return s
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	exe := c.options.Executable
	if exe == "" {
		exe = FindExecutable()
	}
	if exe == "" {
		s.Component.Availability = components.Missing
		return fail(errors.New("缺少清理组件，请使用包含 core/connect-hub-cleanup.exe 的完整安装包；基础 VPN 仍可使用"))
	}
	probe := c.options.Probe
	if probe == nil {
		probe = probeExecutable
	}
	if err := probe(ctx, exe); err != nil {
		s.Component.Availability = components.Incompatible
		return fail(err)
	}
	dir, err := taskio.NewDir(filepath.Join(c.options.DataDir, "cleanup", "tasks"))
	if err != nil {
		return fail(err)
	}
	s.TaskDir = dir
	mutation := request.Operation == contract.Apply || request.Operation == contract.Restore
	// Only mutation journals and a successful scan needed for a later apply
	// survive this invocation. Backups have a separate, persistent owner.
	defer func() {
		if !mutation && (request.Operation != contract.Scan || s.Result.Outcome != "complete") {
			_ = Discard(dir)
		}
	}()
	launch := c.options.Launch
	if launch == nil {
		launch = launchProcess
	}
	type launchResult struct {
		p   Process
		err error
	}
	started := make(chan launchResult, 1)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	var process Process
	var exited <-chan error
	var exitErr error
	var cursor components.Cursor
	var tail taskio.Tail
	var cancelAt time.Time
	var transportErr error
	var handshake bool
	var killed bool
	var cancelSent bool
	start := time.Now()
	lastLease := time.Time{}
	request.BackupRoot = filepath.Join(c.options.DataDir, "cleanup", "backups")
	request.Version = components.Version
	request.RequestID, err = components.NewID()
	if err != nil {
		return fail(err)
	}
	request.Deadline = time.Now().Add(contract.TaskTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(request.Deadline) {
		request.Deadline = d
	}
	s.RequestID = request.RequestID
	// Validate before launching or asking Windows for administrator consent.
	request.InstanceID = "pending"
	if err := request.Check(time.Now()); err != nil {
		return fail(err)
	}
	go func() { p, e := launch(exe, []string{"--task-dir", dir}, mutation); started <- launchResult{p, e} }()
	push()
	consume := func(e components.Event) error {
		if !cursor.Accept(e) {
			return errors.New("清理事件属于旧任务、乱序或无效")
		}
		changed = true
		var update contract.Update
		if len(e.Payload) > 0 {
			if err := components.Decode(bytes.NewReader(e.Payload), &update); err != nil {
				return err
			}
		}
		s.Component.State = e.State
		s.Component.Detail = e.Detail
		if e.Detail != "" {
			s.Logs = append(s.Logs, contract.Text(e.Detail))
			if len(s.Logs) > contract.MaxLogs {
				s.Logs = append([]string(nil), s.Logs[len(s.Logs)-contract.MaxLogs:]...)
			}
		}
		if f := update.Finding; f != nil {
			if len(s.Findings) >= contract.MaxFindings || len(f.ID) > 4096 {
				return errors.New("清理条目超过上限")
			}
			f.Title = contract.Text(f.Title)
			f.Detail = contract.Text(f.Detail)
			f.Group = contract.Text(f.Group)
			s.Findings = append(s.Findings, *f)
		}
		if update.Installed != "" && len(s.Installed) < 32 {
			s.Installed = append(s.Installed, contract.Text(update.Installed))
		}
		if b := update.Backup; b != nil {
			if !components.ValidID(b.ID) || len(s.Backups) >= contract.MaxBackups {
				return errors.New("备份条目无效或超过上限")
			}
			s.Backups = append(s.Backups, *b)
		}
		if update.Result != nil {
			s.Result = *update.Result
		}
		if e.Final && update.Result == nil {
			return errors.New("清理任务缺少最终结果")
		}
		return nil
	}
	for {
		select {
		case lr := <-started:
			started = nil
			if lr.err != nil {
				return fail(lr.err)
			}
			process = lr.p
			start = time.Now() // UAC time is not handshake time.
			ch := make(chan error, 1)
			exited = ch
			go func() { ch <- process.Wait() }()
		case exitErr = <-exited:
			exited = nil
			if handshake {
				if e := tail.Read(filepath.Join(dir, "events.jsonl"), contract.MaxStreamBytes, consume); e != nil {
					transportErr = e
				}
			}
			if transportErr != nil {
				return fail(transportErr)
			}
			if !cursor.Final {
				if !mutation && ctx.Err() != nil && transportErr == nil {
					s.Component.State = components.Disabled
					s.Component.Detail = "扫描或查询已取消"
					s.Result.Outcome = "canceled"
					s.Findings = nil
					s.Installed = nil
					s.Backups = nil
					s.Done = true
					push()
					return s
				}
				return fail(fmt.Errorf("清理组件异常退出，任务未确认完成；记录保存在 %s（%v）", dir, exitErr))
			}
			if exitErr != nil {
				return fail(fmt.Errorf("清理组件退出失败: %w", exitErr))
			}
			s.Done = true
			if s.Result.Outcome != "complete" {
				s.Findings = nil
				s.Installed = nil
			}
			push()
			return s
		case <-ticker.C:
			if time.Since(lastLease) > time.Second {
				if e := taskio.WriteBytes(dir, "lease", nil); e != nil && transportErr == nil {
					transportErr = e
				}
				lastLease = time.Now()
			}
			if !handshake && process != nil {
				var hello components.Hello
				e := taskio.Read(dir, "hello.json", &hello)
				if e == nil {
					e = hello.Check(contract.Capability)
					if e == nil {
						request.InstanceID = hello.InstanceID
						cursor = components.Cursor{InstanceID: hello.InstanceID, RequestID: request.RequestID}
						s.Component.InstanceID = hello.InstanceID
						e = taskio.Write(dir, "request.json", request)
						handshake = e == nil
					}
				}
				if e != nil && !os.IsNotExist(e) {
					transportErr = e
					s.Component.Availability = components.Incompatible
				}
				if time.Since(start) > components.DefaultTimeout && transportErr == nil {
					transportErr = errors.New("清理组件握手超时")
				}
			}
			if handshake && transportErr == nil {
				if e := tail.Read(filepath.Join(dir, "events.jsonl"), contract.MaxStreamBytes, consume); e != nil {
					transportErr = e
				}
			}
			if (ctx.Err() != nil || transportErr != nil || time.Now().After(request.Deadline)) && cancelAt.IsZero() {
				cancelAt = time.Now()
			}
			if !cancelAt.IsZero() && !cursor.Final {
				if s.Component.State != components.Stopping {
					changed = true
				}
				s.Component.State = components.Stopping
				s.Component.Detail = "正在等待当前操作完成并安全停止"
				if handshake && !cancelSent {
					stop := request.Request
					stop.Operation = "cancel"
					cancelSent = taskio.Write(dir, "cancel.json", stop) == nil
				}
				if process != nil && !mutation && time.Since(cancelAt) > 2*time.Second && !killed {
					_ = process.Kill()
					killed = true
				}
			}
			if changed {
				push()
			}
		}
	}
}

// Discard only removes a known task directory after its process has exited.
// Mutation journals and backups are never passed here by the GUI.
func Discard(dir string) error {
	if dir == "" {
		return nil
	}
	if err := taskio.ValidateDir(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.RemoveAll(dir)
}

type limitBuffer struct{ bytes.Buffer }

func (b *limitBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > components.MaxMessageBytes {
		return 0, errors.New("组件版本响应过大")
	}
	return b.Buffer.Write(p)
}
func probeExecutable(ctx context.Context, exe string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "--task-capability")
	hide(cmd)
	var out limitBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("清理组件版本检查失败: %w", err)
	}
	if strings.TrimSpace(out.String()) != contract.Capability {
		return errors.New("清理组件版本不兼容，请更新完整安装包")
	}
	return nil
}
