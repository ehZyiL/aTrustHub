package relay

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestControllerWorkerFollowsEnabledIntent(t *testing.T) {
	_, _, _, c, _ := setupShare(t)
	if c.runDone != nil {
		t.Fatal("disabled restore started a watcher")
	}
	for i := 0; i < 10; i++ {
		if err := c.Enable(context.Background(), EnableOptions{PointID: "p1"}); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		done := c.runDone
		c.mu.Unlock()
		if done == nil {
			t.Fatal("enabled share has no watcher")
		}
		if err := c.Disable(context.Background()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		default:
			t.Fatal("disable returned while its worker was alive")
		}
		c.Wake()
		if err := c.Restore(context.Background()); err != nil {
			t.Fatal(err)
		}
		if c.runDone != nil || c.server != nil {
			t.Fatal("disabled share revived after wake/restore")
		}
	}
}

type cancelledAcquireSink struct {
	*fakeSink
	entered chan struct{}
	source  *fakeSource
}

func (s *cancelledAcquireSink) AcquireSource(ctx context.Context, _ string) (Source, error) {
	close(s.entered)
	<-ctx.Done()
	// A backend may hand back a partially created resource on cancellation.
	return s.source, ctx.Err()
}

func TestDisableCancelsAcquireAndReleasesPartialSource(t *testing.T) {
	p := newFakePersistence()
	sink := &cancelledAcquireSink{fakeSink: newFakeSink("p1"), entered: make(chan struct{}), source: newFakeSource(testSnapshot())}
	c := NewController(p, sink, loopbackNets(), nil, nil)
	t.Cleanup(func() { _ = c.Shutdown(context.Background()) })
	result := make(chan error, 1)
	go func() { result <- c.Enable(context.Background(), EnableOptions{PointID: "p1"}) }()
	<-sink.entered
	stopped := make(chan error, 1)
	go func() { stopped <- c.Disable(context.Background()) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disable did not cancel the in-flight source acquisition")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("enable result = %v", err)
	}
	select {
	case <-sink.source.Done():
	default:
		t.Fatal("partial source was not closed")
	}
	if p.ShareSettings().Enabled || p.secretCount() != 0 || c.runDone != nil {
		t.Fatal("cancelled first enable retained intent, secrets or worker")
	}
}

func TestConcurrentControllerOperationsLeaveNoRuntimeAfterShutdown(t *testing.T) {
	_, _, _, c, _ := setupShare(t)
	var wg sync.WaitGroup
	for n := 0; n < 3; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				_ = c.Enable(context.Background(), EnableOptions{PointID: "p1"})
				_ = c.Disable(context.Background())
				c.Wake()
			}
		}()
	}
	wg.Wait()
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Enable(context.Background(), EnableOptions{PointID: "p1"}); err == nil {
		t.Fatal("shutdown controller restarted")
	}
	if c.runDone != nil || c.server != nil || c.source != nil {
		t.Fatal("shutdown retained runtime resources")
	}
}
