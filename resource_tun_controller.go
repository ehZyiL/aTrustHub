package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/qy/easyconnect/internal/localapps"
)

type resourceTUNStatus struct {
	Running, Busy  bool
	CleanupPending bool
	Error          string
}

type resourceTUNController struct {
	mu, operation sync.Mutex
	status        resourceTUNStatus
	current       localapps.SystemCapture
	cancel        context.CancelFunc
	restore       func() error
	closed        bool
	configs       func() ([]localapps.CaptureConfig, error)
	start         func(context.Context, []localapps.CaptureConfig) (localapps.SystemCapture, error)
	suspendProxy  func() (func() error, error)
	change        func()
}

func (c *resourceTUNController) View() resourceTUNStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	view := c.status
	view.CleanupPending = (c.restore != nil || c.current != nil) && !view.Running
	return view
}
func (c *resourceTUNController) notify() {
	if c.change != nil {
		c.change()
	}
}
func (c *resourceTUNController) Start() {
	c.mu.Lock()
	if c.closed || c.status.Running || c.status.Busy || c.restore != nil || c.current != nil {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.status = resourceTUNStatus{Busy: true}
	c.mu.Unlock()
	c.notify()
	go c.begin(ctx)
}
func (c *resourceTUNController) begin(ctx context.Context) {
	c.operation.Lock()
	defer c.operation.Unlock()
	configs, err := c.configs()
	var run localapps.SystemCapture
	var restore func() error
	if err == nil && ctx.Err() == nil {
		run, err = c.start(ctx, configs)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		restore, err = c.suspendProxy()
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
		c.status = resourceTUNStatus{Error: err.Error()}
		c.mu.Unlock()
		c.notify()
		return
	}
	c.mu.Lock()
	c.current, c.restore = run, restore
	c.status = resourceTUNStatus{Running: true}
	c.mu.Unlock()
	c.notify()
	go c.monitor(ctx, run)
}
func (c *resourceTUNController) monitor(ctx context.Context, run localapps.SystemCapture) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	failed := map[string]bool{}
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
			configs, err := c.configs()
			if err == nil {
				for _, config := range configs {
					if failed[config.Key] {
						continue
					}
					if addErr := run.Add(ctx, config); addErr != nil {
						failed[config.Key] = true
						err = errors.Join(err, addErr)
					}
				}
			}
			if err != nil {
				c.mu.Lock()
				if c.current == run {
					c.status.Error = "部分资源未接管：" + err.Error()
				}
				c.mu.Unlock()
				c.notify()
			}
		}
	}
}
func (c *resourceTUNController) Stop() {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.status.Busy = true
	c.mu.Unlock()
	c.notify()
	go c.stop()
}
func (c *resourceTUNController) stop() error {
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
func (c *resourceTUNController) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	return c.stop()
}
