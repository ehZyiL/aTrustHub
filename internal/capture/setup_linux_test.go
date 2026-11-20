package capture

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func waitSetup(t *testing.T, s *HelperSetup) HelperSetupState {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		v := s.Snapshot()
		if !v.Busy {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("setup did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestHelperSetupSerializesAndRequiresWorkingHandshakeAfterInstall(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var installs atomic.Int32
	s := &HelperSetup{check: func(context.Context) error { return ErrHelperIncompatible }, install: func() error { installs.Add(1); close(started); <-release; return nil }}
	if !s.Install() {
		t.Fatal("first install rejected")
	}
	<-started
	if s.Install() || s.Check() {
		t.Fatal("concurrent authentication or probe started")
	}
	if s.Snapshot().Ready {
		t.Fatal("unverified install reported ready")
	}
	close(release)
	v := waitSetup(t, s)
	if v.Ready || !v.Checked || v.Installing || installs.Load() != 1 {
		t.Fatal("exit status alone trusted", v)
	}
	s.check = func(context.Context) error { return nil }
	if !s.Check() {
		t.Fatal("recheck rejected")
	}
	if !waitSetup(t, s).Ready {
		t.Fatal("compatible service not recognized")
	}
}

func TestHelperSetupCloseCancelsProbeButDoesNotInterruptInstallation(t *testing.T) {
	started, done := make(chan struct{}), make(chan struct{})
	s := &HelperSetup{check: func(ctx context.Context) error { close(started); <-ctx.Done(); close(done); return ctx.Err() }}
	s.Check()
	<-started
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("probe survived shutdown")
	}
	waitSetup(t, s)
	if s.Check() || s.Install() {
		t.Fatal("closed UI started an operation")
	}
	started, done = make(chan struct{}), make(chan struct{})
	s = &HelperSetup{check: func(context.Context) error { return nil }, install: func() error { close(started); <-done; return nil }}
	s.Install()
	<-started
	s.Close()
	if !s.Snapshot().Installing {
		t.Fatal("privileged transaction interrupted on close")
	}
	close(done)
	if !waitSetup(t, s).Ready {
		t.Fatal("authorized installer did not complete")
	}
}

func TestInstallCommandUsesPackagedFilesAndLiteralArguments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "package with spaces $(touch should-not-run)")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "easyconnect-hub")
	if err := os.WriteFile(exe, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := installCommand(exe, 1000); err == nil {
		t.Fatal("incomplete bundle accepted")
	}
	for _, name := range []string{"install-capture-helper.sh", "easyconnect-hub-capture", "easyconnect-hub-capture@.service"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd, err := installCommand(exe, 1000)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/pkexec", "--disable-internal-agent", "/usr/bin/bash", filepath.Join(dir, "install-capture-helper.sh"), "--uid", "1000"}
	if !reflect.DeepEqual(cmd.Args, want) || cmd.Stdin != nil {
		t.Fatal("installation used shell interpolation or credential input")
	}
	if _, err := installCommand(exe, 0); err == nil {
		t.Fatal("root desktop allowed")
	}
	path := filepath.Join(dir, "install-capture-helper.sh")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, path); err != nil {
		t.Fatal(err)
	}
	if _, err := installCommand(exe, 1000); err == nil {
		t.Fatal("external installer symlink accepted")
	}
}

func TestHelperHandshakeCancellationClosesSilentSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan *net.UnixConn, 1)
	go func() {
		c, err := ln.AcceptUnix()
		if err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := dialControl(ctx, path, uint32(os.Getuid())); done <- err }()
	conn := <-accepted
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("silent handshake ignored cancellation")
	}
}

func TestHelperHandshakeRequiresNaturalExitFix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		wantErr error
	}{
		{name: "previous helper requires update", version: 7, wantErr: ErrHelperIncompatible},
		{name: "current helper is ready", version: ProtocolVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sock")
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				done <- writeFrame(conn, frame{Version: tc.version, Type: "hello", Token: strings.Repeat("a", 64)})
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, err := dialControl(ctx, path, uint32(os.Getuid()))
			if client != nil {
				client.conn.Close()
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("handshake: got %v, want %v", err, tc.wantErr)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
