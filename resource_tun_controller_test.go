package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/localapps"
)

type controllerRuntime struct {
	done            chan struct{}
	once            sync.Once
	closes          atomic.Int32
	cleanupFailures atomic.Int32
	failure         error
}

func (r *controllerRuntime) Reconcile(context.Context, []localapps.CaptureConfig) error { return nil }
func (r *controllerRuntime) Done() <-chan struct{}                                      { return r.done }
func (r *controllerRuntime) Err() error                                                 { return r.failure }
func (r *controllerRuntime) Close() error {
	r.closes.Add(1)
	r.once.Do(func() { close(r.done) })
	if r.cleanupFailures.Add(-1) >= 0 {
		return errors.New("cleanup pending")
	}
	return nil
}

func waitController(t *testing.T, c *resourceTUNController, want func(resourceTUNStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
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
	c := &resourceTUNController{configs: func() ([]localapps.CaptureConfig, error) { return []localapps.CaptureConfig{{Key: "A"}}, nil }, start: func(ctx context.Context, _ []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ready:
			return r, nil
		}
	}, suspendProxy: func() (func() error, error) { suspend.Add(1); return func() error { restore.Add(1); return nil }, nil }}
	t.Cleanup(func() { c.Close() })
	c.Start()
	if suspend.Load() != 0 {
		t.Fatal("proxy disabled before runtime ready")
	}
	close(ready)
	waitController(t, c, func(s resourceTUNStatus) bool { return s.Running && !s.Busy })
	if suspend.Load() != 1 {
		t.Fatal("ready runtime did not commit mode switch")
	}
	c.Stop()
	waitController(t, c, func(s resourceTUNStatus) bool { return !s.Running && !s.Busy })
	if restore.Load() != 1 || r.closes.Load() != 1 {
		t.Fatal("mode stop failed to restore")
	}
}

func TestResourceTUNFailedStartupOrCancellationPreservesProxy(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		var touched atomic.Int32
		entered := make(chan struct{})
		c := &resourceTUNController{configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, start: func(ctx context.Context, _ []localapps.CaptureConfig) (localapps.SystemCapture, error) {
			close(entered)
			if cancelled {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return nil, errors.New("UAC rejected")
		}, suspendProxy: func() (func() error, error) { touched.Add(1); return nil, nil }}
		c.Start()
		<-entered
		if cancelled {
			c.Stop()
		}
		waitController(t, c, func(s resourceTUNStatus) bool { return !s.Busy && s.Error != "" })
		if touched.Load() != 0 {
			t.Fatal("failed startup changed proxy")
		}
		c.Close()
	}
}

func TestResourceTUNProxyFailureRollsBackReadyRuntime(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	var restores atomic.Int32
	c := &resourceTUNController{configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, start: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) { return r, nil }, suspendProxy: func() (func() error, error) {
		return func() error { restores.Add(1); return nil }, errors.New("proxy changed externally")
	}}
	c.Start()
	waitController(t, c, func(s resourceTUNStatus) bool { return !s.Busy && s.Error != "" })
	if c.View().Running || r.closes.Load() != 1 || restores.Load() != 1 {
		t.Fatal("failed mode commit leaked runtime")
	}
	c.Close()
}

func TestResourceTUNKeepsFailedStartupCleanupForRetry(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	r.cleanupFailures.Store(1)
	var proxyCalls atomic.Int32
	c := &resourceTUNController{configs: func() ([]localapps.CaptureConfig, error) { return nil, nil }, start: func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error) {
		return r, errors.New("partial startup rollback failed")
	}, suspendProxy: func() (func() error, error) { proxyCalls.Add(1); return nil, nil }}
	c.Start()
	waitController(t, c, func(s resourceTUNStatus) bool { return !s.Busy && s.CleanupPending })
	if c.View().Running || proxyCalls.Load() != 0 {
		t.Fatal("incomplete startup committed proxy mode")
	}
	c.Start()
	if c.View().Busy {
		t.Fatal("new startup admitted while cleanup pending")
	}
	c.Stop()
	waitController(t, c, func(s resourceTUNStatus) bool { return !s.Busy && !s.CleanupPending })
	if r.closes.Load() != 2 {
		t.Fatal("cleanup retry discarded the original runtime")
	}
	c.Close()
}

func TestResourceTUNRetriesProxyRestoreWithoutRepeatingRuntimeStop(t *testing.T) {
	r := &controllerRuntime{done: make(chan struct{})}
	var restores atomic.Int32
	c := &resourceTUNController{current: r, restore: func() error {
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
