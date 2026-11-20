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

func TestDisconnectCancelsDNSBeforeCaptureStartup(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	started := make(chan struct{})
	var launched atomic.Bool
	m.dns.prepare = func(ctx context.Context, _ string, _ CaptureConfig) (aliasBinding, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	m.captureStart = func(context.Context, model.LocalApp, DialFunc) (managedCapture, error) {
		launched.Store(true)
		return &fakeCapture{done: make(chan struct{})}, nil
	}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }, aliasTestConfig("preparing")); err != nil {
		t.Fatal(err)
	}
	<-started
	done := make(chan struct{})
	go func() { m.StopPoint("vpn"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disconnect blocked on DNS preparation")
	}
	if v := m.View("ide"); v.Starting || v.Stopping || v.Running || v.Error != "" || launched.Load() {
		t.Fatalf("cancelled DNS setup continued launching software: %+v", v)
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

func TestAsyncCaptureStartupFailureReportedWithProjectName(t *testing.T) {
	for _, dnsFailure := range []bool{true, false} {
		name := "capture"
		if dnsFailure {
			name = "dns"
		}
		t.Run(name, func(t *testing.T) {
			m := NewManager(nil)
			defer m.Close()
			failure := errors.New("SetIpInterfaceEntry (Win32 87)")
			var launched atomic.Bool
			m.captureStart = func(context.Context, model.LocalApp, DialFunc) (managedCapture, error) {
				launched.Store(true)
				return nil, failure
			}
			var configs []CaptureConfig
			if dnsFailure {
				configs = []CaptureConfig{aliasTestConfig("diagnostics")}
				m.dns.prepare = func(context.Context, string, CaptureConfig) (aliasBinding, error) {
					return nil, failure
				}
			}
			type report struct {
				name string
				err  error
				view View
			}
			reports := make(chan report, 2)
			m.SetErrorHandler(func(name string, err error) {
				// Observers may inspect state: the manager lock must be released.
				reports <- report{name, err, m.View("ide")}
			})
			if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }, configs...); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-reports:
				if got.name != "IDE" || !errors.Is(got.err, failure) || got.view.Running || got.view.Starting || got.view.Error != got.err.Error() {
					t.Fatalf("incomplete asynchronous failure report: %+v", got)
				}
			case <-time.After(time.Second):
				t.Fatal("startup failure was not reported")
			}
			if dnsFailure && launched.Load() {
				t.Fatal("launched after failed network preparation")
			}
			select {
			case got := <-reports:
				t.Fatalf("duplicate report: %+v", got)
			default:
			}
		})
	}
}
