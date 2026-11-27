// Package ctxlock provides cancellable serialization for relay operations.
package ctxlock

import (
	"context"
	"sync"
)

// Mutex is a zero-value ready mutex. It must not be copied after first use.
type Mutex struct {
	once sync.Once
	gate chan struct{}
}

func (m *Mutex) init() { m.once.Do(func() { m.gate = make(chan struct{}, 1) }) }

func (m *Mutex) Lock() { _ = m.LockContext(context.Background()) }

// LockContext leaves no waiter behind when the caller cancels.
func (m *Mutex) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.init()
	select {
	case m.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Mutex) TryLock() bool {
	m.init()
	select {
	case m.gate <- struct{}{}:
		return true
	default:
		return false
	}
}

func (m *Mutex) Unlock() {
	m.init()
	select {
	case <-m.gate:
	default:
		panic("ctxlock: unlock of unlocked mutex")
	}
}
