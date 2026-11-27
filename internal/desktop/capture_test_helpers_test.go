package desktop

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/localapps"
	"github.com/ehzyil/connect-hub/internal/localapps/takeover"
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

func waitController(t *testing.T, c *takeover.Controller, want func(resourceTUNStatus) bool) {
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
