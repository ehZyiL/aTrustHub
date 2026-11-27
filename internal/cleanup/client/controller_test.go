package client

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
)

type controllerRunner func(context.Context, contract.Request, func(Snapshot)) Snapshot

func (r controllerRunner) Run(ctx context.Context, req contract.Request, publish func(Snapshot)) Snapshot {
	return r(ctx, req, publish)
}

func awaitControllerSnapshot(t *testing.T, c *TaskController, want func(Snapshot) bool) Snapshot {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if next := c.Drain(); next != nil && want(*next) {
			return *next
		}
		select {
		case <-deadline:
			t.Fatal("cleanup controller did not publish expected snapshot")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestTaskControllerIsLazyAndBoundsOwnedSnapshots(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	changed := make(chan struct{}, 200)
	c := NewTaskController(controllerRunner(func(_ context.Context, req contract.Request, publish func(Snapshot)) Snapshot {
		calls.Add(1)
		logs := []string{"progress"}
		for i := 0; i < 100; i++ {
			publish(Snapshot{Operation: req.Operation, Logs: logs, Result: contract.Result{OK: i}})
		}
		logs[0] = "mutated after publish"
		close(entered)
		<-release
		return Snapshot{Operation: req.Operation, Done: true}
	}), func() { changed <- struct{}{} })
	t.Cleanup(c.Close)
	if calls.Load() != 0 || c.Drain() != nil {
		t.Fatal("construction started work")
	}
	if !c.Start(context.Background(), contract.Request{Request: components.Request{Operation: contract.List}}) {
		t.Fatal("task refused")
	}
	<-entered
	if c.Start(context.Background(), contract.Request{}) {
		t.Fatal("overlapping task accepted")
	}
	next := c.Drain()
	if next == nil || next.Result.OK != 99 || next.Logs[0] != "progress" || c.Drain() != nil {
		t.Fatalf("mailbox is not a single owned snapshot: %+v", next)
	}
	close(release)
	awaitControllerSnapshot(t, c, func(s Snapshot) bool { return s.Done })
	if calls.Load() != 1 || len(changed) == 0 {
		t.Fatal("task lifecycle or change notification missing")
	}
}

func TestTaskControllerCancellationRestartAndStaleEvents(t *testing.T) {
	var calls atomic.Int32
	oldPublish := make(chan func(Snapshot), 1)
	secondStarted, finishSecond := make(chan struct{}), make(chan struct{})
	c := NewTaskController(controllerRunner(func(ctx context.Context, req contract.Request, publish func(Snapshot)) Snapshot {
		if calls.Add(1) == 1 {
			oldPublish <- publish
			<-ctx.Done()
			return Snapshot{Operation: req.Operation, Done: true, Result: contract.Result{Outcome: "cancelled"}}
		}
		close(secondStarted)
		<-finishSecond
		return Snapshot{Done: true}
	}), nil)
	t.Cleanup(c.Close)
	c.Start(context.Background(), contract.Request{})
	stale := <-oldPublish
	c.Cancel()
	awaitControllerSnapshot(t, c, func(s Snapshot) bool { return s.Done && s.Result.Outcome == "cancelled" })
	if !c.Start(context.Background(), contract.Request{}) {
		t.Fatal("cannot restart after cancellation")
	}
	<-secondStarted
	stale(Snapshot{Logs: []string{"stale"}})
	if c.Drain() != nil {
		t.Fatal("old generation overwrote current task")
	}
	close(finishSecond)
	awaitControllerSnapshot(t, c, func(s Snapshot) bool { return s.Done })
	c.Close()
	stale(Snapshot{})
	if c.Drain() != nil || c.Start(context.Background(), contract.Request{}) {
		t.Fatal("closed controller accepted work or updates")
	}
}

func TestTaskControllerCloseCancelsAtCheckpointAndDiscardsScan(t *testing.T) {
	for _, completed := range []bool{false, true} {
		t.Run(map[bool]string{false: "in flight", true: "undrained result"}[completed], func(t *testing.T) {
			dir, err := taskio.NewDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			entered, cancelled, checkpoint := make(chan struct{}), make(chan struct{}), make(chan struct{})
			published := make(chan struct{}, 1)
			c := NewTaskController(controllerRunner(func(ctx context.Context, req contract.Request, publish func(Snapshot)) Snapshot {
				close(entered)
				if !completed {
					<-ctx.Done()
					close(cancelled)
					<-checkpoint
				}
				return Snapshot{Operation: req.Operation, Done: true, TaskDir: dir}
			}), func() { published <- struct{}{} })
			c.Start(context.Background(), contract.Request{Request: components.Request{Operation: contract.Scan}})
			<-entered
			if completed {
				<-published
			}
			c.Close()
			if !completed {
				<-cancelled
				if taskio.ValidateDir(dir) != nil {
					t.Fatal("task directory removed before safe checkpoint")
				}
				close(checkpoint)
			}
			deadline := time.Now().Add(2 * time.Second)
			for taskio.ValidateDir(dir) == nil && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if taskio.ValidateDir(dir) == nil || c.Drain() != nil {
				t.Fatal("closed task retained scan details")
			}
		})
	}
}
