package localapps

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/workeripc"
)

type fakeAliasBinding struct {
	done chan struct{}
	once sync.Once
}

func (f *fakeAliasBinding) Close() error                                     { f.once.Do(func() { close(f.done) }); return nil }
func (f *fakeAliasBinding) Done() <-chan struct{}                            { return f.done }
func (f *fakeAliasBinding) Exchange(context.Context, []byte) ([]byte, error) { return nil, nil }

func TestDNSAliasPoolKeepsWorkerIdentityAcrossStopsAndRejectsLostController(t *testing.T) {
	var active atomic.Bool
	active.Store(true)
	created := 0
	pool := dnsPool{prepare: func(context.Context, string, CaptureConfig) (aliasBinding, error) {
		created++
		return &fakeAliasBinding{done: make(chan struct{})}, nil
	}}
	t.Cleanup(pool.close)
	config := CaptureConfig{Key: "one-generation", Domains: []string{"corp.test"}, Active: active.Load, MappedDNS: func(context.Context, []byte, string) (workeripc.Message, error) { return workeripc.Message{}, nil }}
	one, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	two, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	one.release()
	two.release()
	three, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	if created != 1 || three.alias != one.alias || three.address != one.address {
		t.Fatal("normal stop/restart changed worker's DNS identity")
	}
	// Losing the helper must cancel every user and require a fresh VPN
	// generation, not silently pair the old worker with a different pool.
	three.alias.Close()
	select {
	case <-three.done:
	case <-time.After(time.Second):
		t.Fatal("helper EOF left DNS serving")
	}
	deadline := time.Now().Add(time.Second)
	for {
		pool.mu.Lock()
		failed := pool.failed[config.Key]
		pool.mu.Unlock()
		if failed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lost controller not recorded")
		}
		time.Sleep(time.Millisecond)
	}
	three.release()
	if b, err := pool.acquire(config); err == nil {
		b.release()
		t.Fatal("ended helper silently changed worker range")
	}
	config.Key = "new-generation"
	four, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(false)
	four.release()
	select {
	case <-four.done:
	case <-time.After(2 * time.Second):
		t.Fatal("disconnected VPN retained DNS listener")
	}
}
