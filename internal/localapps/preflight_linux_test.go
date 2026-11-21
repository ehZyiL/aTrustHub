package localapps

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ehZyiL/connect-hub/internal/model"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

func copyProbeProgram(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "probe")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func startProbeProgram(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd
}

func TestCapturePreflightFindsNativeInstanceAndPreservesProcess(t *testing.T) {
	p := captureProfile(t)
	p.Executable = copyProbeProgram(t, t.TempDir())
	cmd := startProbeProgram(t, p.Executable)
	assertRunning := func(path string) {
		t.Helper()
		check := p
		check.Executable = path
		err := checkCaptureProgram(context.Background(), check)
		if err == nil || !strings.Contains(err.Error(), "PID "+strconv.Itoa(cmd.Process.Pid)) {
			t.Fatalf("running instance not reported: %v", err)
		}
		if _, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe")); err != nil {
			t.Fatal("preflight changed the existing process:", err)
		}
	}
	assertRunning(p.Executable)
	for _, kind := range []string{"symlink", "hardlink"} {
		alias := filepath.Join(t.TempDir(), kind)
		link := os.Link
		if kind == "symlink" {
			link = os.Symlink
		}
		if err := link(p.Executable, alias); err != nil {
			t.Fatal(err)
		}
		assertRunning(alias)
	}
	// A different install with the same filename is not the running program.
	other := p
	other.Executable = copyProbeProgram(t, t.TempDir())
	if err := checkCaptureProgram(context.Background(), other); err != nil {
		t.Fatalf("unrelated executable blocked: %v", err)
	}
	// Atomic upgrades leave the old executable running at the same pathname.
	replacement := copyProbeProgram(t, t.TempDir())
	if err := os.Rename(replacement, p.Executable); err != nil {
		t.Fatal(err)
	}
	assertRunning(p.Executable)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := checkCaptureProgram(context.Background(), p); err != nil {
		t.Fatalf("stopped instance still blocks restart: %v", err)
	}
}

func TestCapturePreflightChecksFilesAndCancellation(t *testing.T) {
	p := captureProfile(t)
	p.Executable = copyProbeProgram(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := checkCaptureProgram(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled launch scanned programs: %v", err)
	}
	if err := checkCaptureProgram(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []model.LocalApp{
		{Executable: filepath.Join(t.TempDir(), "missing")},
		{Executable: t.TempDir()},
		{Executable: p.Executable, WorkDir: p.Executable},
		{Executable: p.Executable, WorkDir: filepath.Join(t.TempDir(), "missing")},
	} {
		if err := checkCaptureProgram(context.Background(), candidate); err == nil {
			t.Fatalf("invalid executable or working directory accepted: %+v", candidate)
		}
	}
	if err := os.Chmod(p.Executable, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkCaptureProgram(context.Background(), p); err == nil {
		t.Fatal("nonexecutable file accepted")
	}
}

func TestCapturePreflightIgnoresOtherOwners(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	// A synthetic proc tree lets this check cover another UID without sudo.
	proc := t.TempDir()
	dir := filepath.Join(proc, "12345")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if pid, err := runningExecutable(context.Background(), proc, os.Getuid()+1, exe, file); err != nil || pid != 0 {
		t.Fatalf("another user's process blocks launch: %d %v", pid, err)
	}
	if pid, err := runningExecutable(context.Background(), proc, os.Getuid(), exe, file); err != nil || pid != 12345 {
		t.Fatalf("current user's instance missing: %d %v", pid, err)
	}
}

func TestCapturePreflightRunsBeforeDNSAndAllowsRetry(t *testing.T) {
	m := NewManager(nil)
	t.Cleanup(func() { _ = m.Close() })
	var prepares, launches atomic.Int32
	m.dns.prepare = func(context.Context, string, CaptureConfig) (aliasBinding, error) {
		prepares.Add(1)
		return nil, errors.New("must not acquire DNS for a rejected program")
	}
	m.captureStart = func(context.Context, model.LocalApp, DialFunc) (managedCapture, error) {
		launches.Add(1)
		return &fakeCapture{done: make(chan struct{})}, nil
	}
	p := captureProfile(t)
	p.Executable = copyProbeProgram(t, t.TempDir())
	cmd := startProbeProgram(t, p.Executable)
	cfg := CaptureConfig{Key: "preflight", Domains: []string{"corp.test"}, MappedDNS: func(context.Context, []byte, string) (workeripc.Message, error) {
		return workeripc.Message{}, nil
	}}
	if err := m.StartCapture(p, unusedDial, func() bool { return true }, cfg); err != nil {
		t.Fatal(err)
	}
	awaitView(t, m, func(v View) bool {
		return !v.Starting && !v.Running && strings.Contains(v.Error, "PID "+strconv.Itoa(cmd.Process.Pid))
	})
	if prepares.Load() != 0 || launches.Load() != 0 {
		t.Fatal("rejected launch acquired DNS or invoked capture")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := m.StartCapture(p, unusedDial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	awaitView(t, m, func(v View) bool { return v.Running && v.Error == "" })
	if launches.Load() != 1 {
		t.Fatal("retry did not start after existing instance exited")
	}
}
