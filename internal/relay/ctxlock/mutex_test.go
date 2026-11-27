package ctxlock

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestMutexCancellationAndReuse(t *testing.T) {
	var m Mutex
	if !m.TryLock() || m.TryLock() {
		t.Fatal("TryLock did not preserve exclusivity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- m.LockContext(ctx) }()
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter returned %v", err)
	}
	m.Unlock()
	if err := m.LockContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context acquired available lock: %v", err)
	}
	var wg sync.WaitGroup
	count := 0
	for range 8 {
		wg.Go(func() {
			for range 100 {
				m.Lock()
				count++
				m.Unlock()
			}
		})
	}
	wg.Wait()
	if count != 800 || !m.TryLock() {
		t.Fatalf("lock lost work or retained cancelled waiter: %d", count)
	}
	m.Unlock()
}
