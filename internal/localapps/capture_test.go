package localapps

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/model"
)

type fakeCapture struct {
	done chan struct{}
	once sync.Once
	err  error
}

func (f *fakeCapture) PID() int              { return 42 }
func (f *fakeCapture) Done() <-chan struct{} { return f.done }
func (f *fakeCapture) Err() error            { return f.err }
func (f *fakeCapture) Close() error          { f.once.Do(func() { close(f.done) }); return nil }

func captureProfile() model.LocalApp {
	return model.LocalApp{ID: "ide", Name: "IDE", PointID: "vpn", Mode: model.LocalAppCapture, Executable: "/usr/bin/true"}
}
func unusedDial(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}

func awaitView(t *testing.T, m *Manager, condition func(View) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition(m.View("ide")) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("unexpected state: %+v", m.View("ide"))
}

func TestDisconnectCancelsCaptureBeforeProgramRelease(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	started, exited := make(chan struct{}), make(chan struct{})
	m.captureStart = func(ctx context.Context, p model.LocalApp, dial DialFunc) (managedCapture, error) {
		close(started)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	<-started
	if !m.View("ide").Starting {
		t.Fatal("pending capture not shown")
	}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }); err == nil {
		t.Fatal("duplicate pending launch accepted")
	}
	m.StopPoint("vpn")
	select {
	case <-exited:
	default:
		t.Fatal("StopPoint returned before pending launch was cancelled")
	}
	v := m.View("ide")
	if v.Running || v.Starting || v.Stopping {
		t.Fatalf("pending state retained: %+v", v)
	}
}

func TestCaptureHelperFailureUpdatesStateAndAllowsRestart(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	process := &fakeCapture{done: make(chan struct{}), err: errors.New("capture rules disappeared")}
	m.captureStart = func(context.Context, model.LocalApp, DialFunc) (managedCapture, error) { return process, nil }
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	awaitView(t, m, func(v View) bool { return v.Running && v.PID == 42 })
	process.Close()
	awaitView(t, m, func(v View) bool { return !v.Running && v.Error == "capture rules disappeared" })
	process = &fakeCapture{done: make(chan struct{})}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	awaitView(t, m, func(v View) bool { return v.Running && v.Error == "" })
	m.StopPoint("vpn")
	if m.View("ide").Running {
		t.Fatal("capture still running")
	}
}

func TestManagerCloseWaitsForCaptureStartupRollback(t *testing.T) {
	m := NewManager(nil)
	rollback := make(chan struct{})
	started := make(chan struct{})
	m.captureStart = func(ctx context.Context, p model.LocalApp, d DialFunc) (managedCapture, error) {
		close(started)
		<-ctx.Done()
		<-rollback
		return nil, ctx.Err()
	}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }); err != nil {
		t.Fatal(err)
	}
	<-started
	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	awaitView(t, m, func(v View) bool { return v.Stopping })
	select {
	case <-done:
		t.Fatal("Close skipped rollback")
	default:
	}
	close(rollback)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close hung")
	}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }); err == nil {
		t.Fatal("closed manager accepted launch")
	}
}

func TestReconnectedVPNReleasesOldCapture(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	var active atomic.Bool
	active.Store(true)
	process := &fakeCapture{done: make(chan struct{})}
	m.captureStart = func(context.Context, model.LocalApp, DialFunc) (managedCapture, error) { return process, nil }
	if err := m.StartCapture(captureProfile(), unusedDial, active.Load); err != nil {
		t.Fatal(err)
	}
	awaitView(t, m, func(v View) bool { return v.Running })
	active.Store(false)
	m.StopExpiredCaptures()
	if v := m.View("ide"); v.Running || v.Starting || v.Stopping {
		t.Fatalf("stale capture retained: %+v", v)
	}
	select {
	case <-process.done:
	default:
		t.Fatal("stale capture was not released")
	}
	if err := m.StartCapture(captureProfile(), unusedDial, active.Load); err == nil {
		t.Fatal("expired VPN accepted a new launch")
	}
}
