package client

import (
	"context"
	"sync"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
)

// Runner executes one cleanup task and returns its final snapshot.
type Runner interface {
	Run(context.Context, contract.Request, func(Snapshot)) Snapshot
}

// TaskController owns background execution and a single-slot snapshot mailbox.
// Its consumer decides when to drain updates and which details to display.
type TaskController struct {
	mu         sync.Mutex
	runner     Runner
	changed    func()
	pending    *Snapshot
	cancel     context.CancelFunc
	generation uint64
	running    bool
	closed     bool
}

func NewTaskController(runner Runner, changed func()) *TaskController {
	return &TaskController{runner: runner, changed: changed}
}

// Start refuses overlapping work and starts nothing after Close.
func (c *TaskController) Start(parent context.Context, request contract.Request) bool {
	c.mu.Lock()
	if c.closed || c.running || c.runner == nil {
		c.mu.Unlock()
		return false
	}
	ctx, cancel := context.WithCancel(parent)
	c.cancel = cancel
	c.running = true
	c.generation++
	generation := c.generation
	c.pending = nil
	request.Selected = append([]string(nil), request.Selected...)
	c.mu.Unlock()
	go func() {
		defer cancel()
		publish := func(v Snapshot) {
			// Completion is published after Run returns, so a consumer cannot
			// observe "done" while the component is still owned by this task.
			if v.Done {
				return
			}
			c.mu.Lock()
			accepted := !c.closed && c.running && c.generation == generation
			if accepted {
				copy := v.Clone()
				c.pending = &copy
			}
			c.mu.Unlock()
			if accepted {
				c.notify()
			}
		}
		result := c.runner.Run(ctx, request, publish)
		c.mu.Lock()
		accepted := !c.closed && c.generation == generation
		if c.generation == generation {
			c.running = false
			c.cancel = nil
		}
		if accepted {
			copy := result.Clone()
			c.pending = &copy
		}
		c.mu.Unlock()
		if accepted {
			c.notify()
		} else if result.Operation == contract.Scan {
			_ = Discard(result.TaskDir)
		}
	}()
	return true
}

func (c *TaskController) notify() {
	if c.changed != nil {
		c.changed()
	}
}

// Drain transfers the newest snapshot to the consumer and releases the mailbox.
func (c *TaskController) Drain() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := c.pending
	c.pending = nil
	return next
}

// Cancel asks the runner to stop at its existing safe checkpoint.
func (c *TaskController) Cancel() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Close rejects subsequent updates and requests cancellation without killing a
// mutation mid-checkpoint. The runner retains its task directory until it exits.
func (c *TaskController) Close() {
	c.mu.Lock()
	c.closed = true
	next := c.pending
	c.pending = nil
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if next != nil && next.Done && next.Operation == contract.Scan {
		_ = Discard(next.TaskDir)
	}
}
