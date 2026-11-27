package relay

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay/contract"
)

type pairQueueContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *pairQueueContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestShareRegressionCancelledQueuedPairControl(t *testing.T) {
	state, err := newPairingState(context.Background(), &memoryDevices{}, "review-share", "review-fingerprint", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = state.control(context.Background(), contract.PairCommand{Operation: "create"}); err != nil {
		t.Fatal(err)
	}
	controller := &Controller{server: &Server{pairing: state}}
	controller.opMu.Lock()
	unlock := sync.OnceFunc(controller.opMu.Unlock)
	defer unlock()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &pairQueueContext{Context: base, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := controller.PairControl(ctx, contract.PairCommand{Operation: "cancel"})
		result <- err
	}()
	awaitStartupTest(t, ctx.waiting)
	cancel()
	returned := false
	select {
	case err = <-result:
		returned = true
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled queued command returned %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("cancelled PairControl still waits for opMu")
	}
	unlock()
	if !returned {
		select {
		case err = <-result:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled command dispatched after unlock: err=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("PairControl did not finish after unlocking")
		}
	}
	view, err := state.control(context.Background(), contract.PairCommand{Operation: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if view.Invitation == nil || view.Invitation.Cancelled {
		t.Error("cancelled queued command still changed the active invitation")
	}
}

func TestPairControlCancelledWhilePairingStateBusy(t *testing.T) {
	state, err := newPairingState(context.Background(), &memoryDevices{}, "test-share", "fingerprint", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	unlock := sync.OnceFunc(state.mu.Unlock)
	defer unlock()
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &pairQueueContext{Context: base, waiting: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := state.control(ctx, contract.PairCommand{Operation: "create"})
		result <- err
	}()
	awaitStartupTest(t, ctx.waiting)
	cancel()
	if err := awaitStartupTest(t, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled queued create returned %v", err)
	}
	unlock()
	v, err := state.control(context.Background(), contract.PairCommand{Operation: "list"})
	if err != nil || v.Invitation != nil {
		t.Fatalf("cancelled create changed invitation: %+v, %v", v, err)
	}
}

func TestCancelledQueuedPauseAndResumeLeaveIntentUnchanged(t *testing.T) {
	for _, operation := range []string{"pause", "resume"} {
		t.Run(operation, func(t *testing.T) {
			p := newFakePersistence()
			p.settings = Settings{Enabled: true, Paused: operation == "resume"}
			c := NewController(p, nil, nil, nil, nil)
			c.opMu.Lock()
			unlock := sync.OnceFunc(c.opMu.Unlock)
			defer unlock()
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &pairQueueContext{Context: base, waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				if operation == "pause" {
					result <- c.PauseSharing(ctx)
				} else {
					result <- c.ResumeSharing(ctx)
				}
			}()
			awaitStartupTest(t, ctx.waiting)
			cancel()
			if err := awaitStartupTest(t, result); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled %s returned %v", operation, err)
			}
			unlock()
			if got := c.Settings(); !got.Enabled || got.Paused != (operation == "resume") {
				t.Fatalf("cancelled %s changed intent: %+v", operation, got)
			}
		})
	}
}
