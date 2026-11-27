package takeover

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/localapps"
)

type controllerRuntime struct {
	done            chan struct{}
	once            sync.Once
	closes          atomic.Int32
	cleanupFailures atomic.Int32
	failure         error
	reconcile       func(context.Context, []localapps.CaptureConfig) error
}

func (r *controllerRuntime) Reconcile(ctx context.Context, configs []localapps.CaptureConfig) error {
	if r.reconcile != nil {
		return r.reconcile(ctx, configs)
	}
	return nil
}
func (r *controllerRuntime) Done() <-chan struct{} { return r.done }
func (r *controllerRuntime) Err() error            { return r.failure }
func (r *controllerRuntime) Close() error {
	r.closes.Add(1)
	r.once.Do(func() { close(r.done) })
	if r.cleanupFailures.Add(-1) >= 0 {
		return errors.New("cleanup pending")
	}
	return nil
}

func waitController(t *testing.T, c *Controller, want func(Status) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if want(c.View()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("controller did not settle", c.View())
}

func TestResourceTUNSwitchCommitsProxyOnlyAfterRuntimeReady(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	var suspend, restore atomic.Int32
	ready := make(chan struct{})
	c := &Controller{Configs: func() ([]localapps.CaptureConfig, error) { return []localapps.CaptureConfig{{Key: "A"}}, nil }, StartCapture: func(ctx context.Context, _ []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
			return r, nil
		}
	}, SuspendProxy: func() (func() error, error) { suspend.Add(1); return func() error { restore.Add(1); return nil }, nil }}
	t.Cleanup(func() { c.Close() })
	c.Start()
	if suspend.Load() != 0 {
		t.Fatal("proxy disabled before runtime ready")
	}
	close(ready)
	waitController(t, c, func(s Status) bool { return s.Running && !s.Busy })
	if suspend.Load() != 1 {
		t.Fatal("ready runtime did not commit mode switch")
	}
	c.Stop()
	waitController(t, c, func(s Status) bool { return !s.Running && !s.Busy })
	if restore.Load() != 1 || r.closes.Load() != 1 {
		t.Fatal("mode stop failed to restore")
	}
}

func TestResourceTUNFailedStartupOrCancellationPreservesProxy(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		var touched atomic.Int32
		entered := make(chan struct{})
		c := &Controller{Configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, StartCapture: func(ctx context.Context, _ []localapps.CaptureConfig) (localapps.SystemCapture, error) {
			close(entered)
			if cancelled {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, errors.New("UAC rejected")
		}, SuspendProxy: func() (func() error, error) { touched.Add(1); return nil, nil }}
		c.Start()
		<-entered
		if cancelled {
			c.Stop()
		}
		waitController(t, c, func(s Status) bool { return !s.Busy && s.Error != "" })
		if touched.Load() != 0 {
			t.Fatal("failed startup changed proxy")
		}
		c.Close()
	}
}

func TestResourceTUNProxyFailureRollsBackReadyRuntime(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	var restores atomic.Int32
	c := &Controller{Configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, StartCapture: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) { return r, nil }, SuspendProxy: func() (func() error, error) {
		return func() error { restores.Add(1); return nil }, errors.New("proxy changed externally")
	}}
	c.Start()
	waitController(t, c, func(s Status) bool { return !s.Busy && s.Error != "" })
	if c.View().Running || r.closes.Load() != 1 || restores.Load() != 1 {
		t.Fatal("failed mode commit leaked runtime")
	}
	c.Close()
}

func TestResourceTUNKeepsFailedStartupCleanupForRetry(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	r.cleanupFailures.Store(1)
	var proxyCalls atomic.Int32
	c := &Controller{Configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, StartCapture: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		return r, errors.New("partial startup rollback failed")
	}, SuspendProxy: func() (func() error, error) { proxyCalls.Add(1); return nil, nil }}
	c.Start()
	waitController(t, c, func(s Status) bool { return !s.Busy && s.CleanupPending })
	if c.View().Running || proxyCalls.Load() != 0 {
		t.Fatal("incomplete startup committed proxy mode")
	}
	c.Start()
	if c.View().Busy {
		t.Fatal("new startup admitted while cleanup pending")
	}
	c.Stop()
	waitController(t, c, func(s Status) bool { return !s.Busy && !s.CleanupPending })
	if r.closes.Load() != 2 {
		t.Fatal("cleanup retry discarded the original runtime")
	}
	c.Close()
}

// N8: one gateway that cannot be captured must not cancel the ones that can.
func TestResourceTUNAcceptsUsableSubsetWhenOneGatewayIsSkipped(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	var started atomic.Int32
	c := &Controller{
		Configs: func() ([]localapps.CaptureConfig, error) {
			return []localapps.CaptureConfig{{Key: "A"}}, PartialError{Reasons: []string{"B 不支持严格 VPN 拨号"}}
		},
		StartCapture: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
			started.Add(1)
			return r, nil
		},
		SuspendProxy: func() (func() error, error) { return func() error { return nil }, nil },
	}
	t.Cleanup(func() { c.Close() })
	c.Start()
	waitController(t, c, func(s Status) bool { return s.Running })
	if started.Load() != 1 {
		t.Fatal("the usable subset was not started")
	}
	if got := c.View().Error; !strings.Contains(got, "B 不支持严格 VPN 拨号") {
		t.Fatalf("status does not name the skipped gateway: %q", got)
	}
}

// A configuration error that leaves nothing to capture still refuses to start.
func TestResourceTUNFatalConfigErrorStopsStart(t *testing.T) {
	var started atomic.Int32
	c := &Controller{
		Configs: func() ([]localapps.CaptureConfig, error) {
			return nil, errors.New("请先登录至少一个加入统一资源池的网关")
		},
		StartCapture: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
			started.Add(1)
			return &controllerRuntime{done: make(chan struct{})}, nil
		},
		SuspendProxy: func() (func() error, error) { return func() error { return nil }, nil },
	}
	t.Cleanup(func() { c.Close() })
	c.Start()
	waitController(t, c, func(s Status) bool { return !s.Busy && s.Error != "" })
	if started.Load() != 0 {
		t.Fatal("a fatal configuration error still started the runtime")
	}
}

func TestResourceTUNRetriesProxyRestoreWithoutRepeatingRuntimeStop(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	var restores atomic.Int32
	c := &Controller{current: r, restore: func() error {
		if restores.Add(1) == 1 {
			return errors.New("proxy registry temporarily unavailable")
		}
		return nil
	}}
	if err := c.stop(); err == nil || !c.View().CleanupPending {
		t.Fatal("failed proxy restore was lost", err)
	}
	if err := c.stop(); err != nil || c.View().CleanupPending || r.closes.Load() != 1 || restores.Load() != 2 {
		t.Fatal("retry did not preserve proxy-only cleanup", err)
	}
}

func TestRuntimeExitStopsTakeoverAndRestoresProxy(t *testing.T) {
	for _, failure := range []error{nil, errors.New("runtime failed")} {
		r := &controllerRuntime{done: make(chan struct{}), failure: failure}
		var restored atomic.Int32
		c := &Controller{
			Configs:      func() ([]localapps.CaptureConfig, error) { return nil, nil },
			StartCapture: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) { return r, nil },
			SuspendProxy: func() (func() error, error) { return func() error { restored.Add(1); return nil }, nil },
		}
		c.Start()
		waitController(t, c, func(s Status) bool { return s.Running })
		r.once.Do(func() { close(r.done) })
		waitController(t, c, func(s Status) bool { return !s.Running && !s.Busy && s.Error != "" })
		if restored.Load() != 1 {
			t.Fatal("runtime exit did not restore proxy")
		}
		c.Close()
		c.Start()
		if c.View().Running || c.View().Busy {
			t.Fatal("closed takeover restarted")
		}
	}
}

func TestMonitorReconcilesUsableSubsetAndReportsBothErrors(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{}), reconcile: func(context.Context, []localapps.CaptureConfig) error {
		return errors.New("route conflict")
	}}
	var configs atomic.Int32
	var notified atomic.Int32
	c := &Controller{
		Configs: func() ([]localapps.CaptureConfig, error) {
			if configs.Add(1) > 1 {
				return []localapps.CaptureConfig{{Key: "A"}}, PartialError{Reasons: []string{"B offline"}}
			}
			return nil, nil
		},
		StartCapture: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) { return r, nil },
		SuspendProxy: func() (func() error, error) { return func() error { return nil }, nil },
		Changed:      func() { notified.Add(1) },
	}
	t.Cleanup(func() { c.Close() })
	c.Start()
	waitController(t, c, func(s Status) bool {
		return s.Running && strings.Contains(s.Error, "B offline") && strings.Contains(s.Error, "route conflict")
	})
	if notified.Load() < 2 {
		t.Fatal("reconcile failure did not notify consumer")
	}
}
