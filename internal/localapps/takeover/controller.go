package takeover

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/localapps"
)

// Status is the current resource takeover state.
type Status struct {
	Running, Busy  bool
	CleanupPending bool
	Error          string
}

// Controller owns resource takeover and its proxy restoration lifecycle.
// Set its callbacks before the first Start; they must not be changed while running.
type Controller struct {
	mu, operation sync.Mutex
	status        Status
	current       localapps.SystemCapture
	cancel        context.CancelFunc
	restore       func() error
	closed        bool
	Configs       func() ([]localapps.CaptureConfig, error)
	StartCapture  func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error)
	SuspendProxy  func() (func() error, error)
	Changed       func()
}

func (c *Controller) View() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	view := c.status
	view.CleanupPending = (c.restore != nil || c.current != nil) && !view.Running
	return view
}
func (c *Controller) notify() {
	if c.Changed != nil {
		c.Changed()
	}
}
func (c *Controller) Start() {
	c.mu.Lock()
	if c.closed || c.status.Running || c.status.Busy || c.restore != nil || c.current != nil {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.status = Status{Busy: true}
	c.mu.Unlock()
	c.notify()
	go c.begin(ctx)
}
func (c *Controller) begin(ctx context.Context) {
	c.operation.Lock()
	defer c.operation.Unlock()
	configs, err := c.Configs()
	// A gateway that cannot be captured must not cancel the ones that can: the
	// usable subset still gets installed and the reason is reported in the
	// status line instead of failing the whole takeover.
	partialNote := ""
	var partial PartialError
	if err != nil && errors.As(err, &partial) {
		err = nil
		partialNote = partial.Error()
	}
	var run localapps.SystemCapture
	var restore func() error
	if err == nil && ctx.Err() == nil {
		run, err = c.StartCapture(ctx, configs)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		restore, err = c.SuspendProxy()
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		if run != nil {
			if closeErr := run.Close(); closeErr != nil {
				err = errors.Join(err, closeErr)
				c.mu.Lock()
				c.current = run
				c.mu.Unlock()
			}
		}
		if restore != nil {
			if restoreErr := restore(); restoreErr != nil {
				err = errors.Join(err, restoreErr)
				c.mu.Lock()
				c.restore = restore
				c.mu.Unlock()
			}
		}
		c.mu.Lock()
		c.status = Status{Error: err.Error()}
		c.mu.Unlock()
		c.notify()
		return
	}
	c.mu.Lock()
	c.current, c.restore = run, restore
	c.status = Status{Running: true, Error: partialNote}
	c.mu.Unlock()
	c.notify()
	go c.monitor(ctx, run)
}
func (c *Controller) monitor(ctx context.Context, run localapps.SystemCapture) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-run.Done():
			c.mu.Lock()
			if c.current == run {
				err := run.Err()
				if err == nil {
					err = errors.New("系统捕获已停止")
				}
				c.status.Error = err.Error()
			}
			c.mu.Unlock()
			c.Stop()
			return
		case <-tick.C:
			configs, err := c.Configs()
			// Same rule as begin: an uncapturable gateway degrades the status
			// line, it does not stop reconciling the rest.
			note := ""
			var partial PartialError
			if err != nil && errors.As(err, &partial) {
				err = nil
				note = partial.Error()
			}
			if err == nil {
				err = run.Reconcile(ctx, configs)
			}
			if ctx.Err() != nil {
				return
			}
			message := note
			if err != nil {
				if message != "" {
					message += "；"
				}
				message += "部分资源未接管：" + err.Error()
			}
			c.mu.Lock()
			changed := c.current == run && c.status.Error != message
			if changed {
				c.status.Error = message
			}
			c.mu.Unlock()
			if changed {
				c.notify()
			}
		}
	}
}
func (c *Controller) Stop() {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.status.Busy = true
	c.mu.Unlock()
	c.notify()
	go c.stop()
}
func (c *Controller) stop() error {
	c.operation.Lock()
	defer c.operation.Unlock()
	c.mu.Lock()
	run, restore := c.current, c.restore
	c.current, c.restore = nil, nil
	c.mu.Unlock()
	var err error
	if run != nil {
		err = run.Close()
		if err != nil {
			c.mu.Lock()
			c.current = run
			c.mu.Unlock()
		}
	}
	if restore != nil {
		if restoreErr := restore(); restoreErr != nil {
			err = errors.Join(err, restoreErr)
			c.mu.Lock()
			c.restore = restore
			c.mu.Unlock()
		}
	}
	c.mu.Lock()
	c.status.Running, c.status.Busy = false, false
	if err != nil {
		c.status.Error = err.Error()
	}
	c.mu.Unlock()
	c.notify()
	return err
}
func (c *Controller) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	return c.stop()
}

// PartialError reports skipped gateways while keeping the usable subset active.
type PartialError struct{ Reasons []string }

func (e PartialError) Error() string {
	return "部分网关未接管：" + strings.Join(e.Reasons, "；")
}
