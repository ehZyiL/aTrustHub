package client_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/cleanup/client"
	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/service"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

// This child executes only the fixture handler. It never invokes Scan, Apply,
// RestoreBackup, elevation, a real uninstaller or any system modification.
func TestCleanupSubprocess(t *testing.T) {
	if os.Getenv("CONNECT_HUB_CLEANUP_FIXTURE") != "1" {
		return
	}
	mode := os.Getenv("CONNECT_HUB_CLEANUP_MODE")
	if mode == "crash" {
		os.Exit(7)
	}
	dir := os.Args[len(os.Args)-1]
	err := service.ServeTask(dir, func(ctx context.Context, dir string, req contract.Request, emit service.Emit) (contract.Result, error) {
		switch mode {
		case "cancel":
			_ = emit("等待安全检查点", contract.Update{})
			<-ctx.Done()
			time.Sleep(120 * time.Millisecond) // One indivisible fixture operation.
			return contract.Result{OK: 1, BackupID: "kept"}, ctx.Err()
		case "failed":
			return contract.Result{Failed: 1}, errors.New("测试操作失败")
		case "large":
			for i := 0; i < 400; i++ {
				if err := emit(fmt.Sprintf("progress-%d", i), contract.Update{}); err != nil {
					return contract.Result{}, err
				}
			}
			for i := 0; i < contract.MaxFindings; i++ {
				f := contract.Finding{ID: fmt.Sprint(i), Title: strings.Repeat("x", 128)}
				if err := emit("", contract.Update{Finding: &f}); err != nil {
					return contract.Result{}, err
				}
			}
		case "scan":
			if err := emit("fixture scan", contract.Update{Finding: &contract.Finding{ID: "fixture", Title: "test", Selected: true}}); err != nil {
				return contract.Result{}, err
			}
		case "restore":
			return contract.Result{OK: 2, BackupID: req.BackupID}, nil
		}
		return contract.Result{Total: 1}, nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(0)
}

type trackedProcess struct {
	cmd           *exec.Cmd
	active, kills *atomic.Int32
	diagnostics   *bytes.Buffer
}

func (p *trackedProcess) Wait() error {
	defer p.active.Add(-1)
	err := p.cmd.Wait()
	if err != nil {
		return fmt.Errorf("%w: %s", err, p.diagnostics.String())
	}
	return nil
}
func (p *trackedProcess) Kill() error { p.kills.Add(1); return p.cmd.Process.Kill() }

func fixture(t *testing.T, mode string) (*client.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	active, kills := new(atomic.Int32), new(atomic.Int32)
	c := client.New(client.Options{Executable: os.Args[0], DataDir: t.TempDir(), Probe: func(context.Context, string) error { return nil }, Launch: func(exe string, args []string, elevated bool) (client.Process, error) {
		cmd := exec.Command(exe, "-test.run=^TestCleanupSubprocess$", "--", args[len(args)-1])
		cmd.Env = append(os.Environ(), "CONNECT_HUB_CLEANUP_FIXTURE=1", "CONNECT_HUB_CLEANUP_MODE="+mode)
		diagnostics := &bytes.Buffer{}
		cmd.Stderr = diagnostics
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		active.Add(1)
		return &trackedProcess{cmd, active, kills, diagnostics}, nil
	}})
	return c, active, kills
}

func TestTaskProcessExitsAndRestartsTenTimes(t *testing.T) {
	c, active, kills := fixture(t, "scan")
	if active.Load() != 0 {
		t.Fatal("constructor launched a process")
	}
	seen := map[string]bool{}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s := c.Run(ctx, contract.Request{Request: components.Request{Operation: contract.Scan}}, nil)
		cancel()
		if !s.Done || s.Result.Outcome != "complete" || len(s.Findings) != 1 || active.Load() != 0 {
			t.Fatalf("cycle %d: %+v active=%d", i, s, active.Load())
		}
		if seen[s.TaskDir] {
			t.Fatal("task directory reused")
		}
		seen[s.TaskDir] = true
		if err := client.Discard(s.TaskDir); err != nil {
			t.Fatal(err)
		}
	}
	if kills.Load() != 0 {
		t.Fatal("normal exit required kill")
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	t.Logf("cleanup cycles=10 retained_heap_before=%d after=%d active_children=%d", before.HeapAlloc, after.HeapAlloc, active.Load())
	if after.HeapAlloc > before.HeapAlloc+2<<20 {
		t.Fatal("ten cleanup tasks retained more than the 2 MiB investigation budget")
	}
}

func TestOrphanedMutationStopsAtCheckpoint(t *testing.T) {
	dir, err := taskio.NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCleanupSubprocess$", "--", dir)
	cmd.Env = append(os.Environ(), "CONNECT_HUB_CLEANUP_FIXTURE=1", "CONNECT_HUB_CLEANUP_MODE=cancel")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var hello components.Hello
	deadline := time.Now().Add(5 * time.Second)
	for taskio.Read(dir, "hello.json", &hello) != nil {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("no hello")
		}
		time.Sleep(20 * time.Millisecond)
	}
	req := contract.Request{Request: components.Request{Version: components.Version, InstanceID: hello.InstanceID, RequestID: "orphan", Operation: contract.Restore, Deadline: time.Now().Add(time.Minute)}, BackupID: "fixture"}
	if err = taskio.Write(dir, "request.json", req); err != nil {
		_ = cmd.Process.Kill()
		<-done
		t.Fatal(err)
	}
	// No Hub lease and no cancel message: simulate a vanished parent.
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(contract.LeaseTimeout + 5*time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatal("orphaned mutation never stopped")
	}
	var tail taskio.Tail
	var final components.Event
	if err = tail.Read(filepath.Join(dir, "events.jsonl"), contract.MaxStreamBytes, func(e components.Event) error {
		if e.Final {
			final = e
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !final.Final || !strings.Contains(string(final.Payload), "canceled") {
		t.Fatalf("orphan did not leave a canceled final result: %+v", final)
	}
}

func TestPackagedCleanupReadOnly(t *testing.T) {
	exe := os.Getenv("CONNECT_HUB_TEST_CLEANUP_EXE")
	if exe == "" {
		t.Skip("set CONNECT_HUB_TEST_CLEANUP_EXE for packaged read-only validation")
	}
	c := client.New(client.Options{Executable: exe, DataDir: t.TempDir()})
	for _, op := range []string{contract.Scan, contract.List} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		s := c.Run(ctx, contract.Request{Request: components.Request{Operation: op}}, nil)
		cancel()
		if !s.Done || s.Result.Outcome != "complete" {
			t.Fatalf("packaged %s failed: %+v", op, s.Component)
		}
		t.Logf("packaged operation=%s outcome=%s displayed_findings=%d total=%d", op, s.Result.Outcome, len(s.Findings), s.Result.Total)
		if op == contract.Scan {
			if err := client.Discard(s.TaskDir); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestMutationCancellationWaitsForCheckpoint(t *testing.T) {
	c, active, kills := fixture(t, "cancel")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var cancelAt time.Time
	s := c.Run(ctx, contract.Request{Request: components.Request{Operation: contract.Restore}, BackupID: "kept"}, func(s client.Snapshot) {
		if s.Component.State == components.Running && cancelAt.IsZero() {
			cancelAt = time.Now()
			cancel()
		}
	})
	if s.Result.Outcome != "canceled" || s.Result.OK != 1 || s.Result.BackupID != "kept" || kills.Load() != 0 || active.Load() != 0 {
		t.Fatalf("unsafe stop: %+v active=%d kills=%d", s, active.Load(), kills.Load())
	}
	if time.Since(cancelAt) < 120*time.Millisecond {
		t.Fatal("reported cancellation before checkpoint")
	}
	if _, err := os.Stat(s.TaskDir); err != nil {
		t.Fatal("mutation journal discarded", err)
	}
}

func TestTaskBoundedSnapshots(t *testing.T) {
	c, active, _ := fixture(t, "large")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s := c.Run(ctx, contract.Request{Request: components.Request{Operation: contract.Scan}}, func(s client.Snapshot) {
		if len(s.Logs) > contract.MaxLogs || len(s.Findings) > contract.MaxFindings {
			t.Error("unbounded snapshot")
		}
	})
	if s.Result.Outcome != "complete" || len(s.Findings) != contract.MaxFindings || active.Load() != 0 {
		t.Fatalf("incomplete bounded scan: %+v", s.Component)
	}
	if err := client.Discard(s.TaskDir); err != nil {
		t.Fatal(err)
	}
}

func TestTaskFailureCrashAndRestore(t *testing.T) {
	for _, mode := range []string{"failed", "crash", "restore"} {
		t.Run(mode, func(t *testing.T) {
			c, active, _ := fixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s := c.Run(ctx, contract.Request{Request: components.Request{Operation: contract.Restore}, BackupID: "fixture"}, nil)
			if active.Load() != 0 || !s.Done {
				t.Fatal("child not joined")
			}
			if mode == "restore" {
				if s.Result.Outcome != "complete" || s.Result.OK != 2 {
					t.Fatalf("restore result %+v", s)
				}
			} else if s.Result.Outcome != "failed" || s.Component.State != components.Failed {
				t.Fatalf("failure concealed: %+v", s)
			}
		})
	}
}

func TestProbeAndElevationFailureNeverRunWork(t *testing.T) {
	for _, mode := range []string{"incompatible", "denied"} {
		t.Run(mode, func(t *testing.T) {
			launched := 0
			c := client.New(client.Options{Executable: os.Args[0], DataDir: t.TempDir(), Probe: func(context.Context, string) error {
				if mode == "incompatible" {
					return errors.New("版本不兼容")
				}
				return nil
			}, Launch: func(string, []string, bool) (client.Process, error) {
				launched++
				return nil, errors.New("用户取消了管理员授权")
			}})
			s := c.Run(context.Background(), contract.Request{Request: components.Request{Operation: contract.Restore}, BackupID: "fixture"}, nil)
			if !s.Done || s.Result.Outcome != "failed" {
				t.Fatalf("failure hidden %+v", s)
			}
			if mode == "incompatible" && (launched != 0 || s.Component.Availability != components.Incompatible) {
				t.Fatal("launched incompatible component")
			}
		})
	}
}

func TestDiscardRejectsOtherDirectories(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if client.Discard(root) == nil {
		t.Fatal("discard accepted unrelated directory")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
}
