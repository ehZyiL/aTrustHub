package localapps

import (
	"context"
	"errors"
	"net"
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

func aliasTestConfig(key string) CaptureConfig {
	return CaptureConfig{Key: key, Domains: []string{"corp.test"}, Active: func() bool { return true }, MappedDNS: func(context.Context, []byte, string) (workeripc.Message, error) {
		return workeripc.Message{}, nil
	}}
}

func TestDNSPrepareCancellationRollsBackAndAllowsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 1)
	alias := &fakeAliasBinding{done: make(chan struct{})}
	var calls atomic.Int32
	pool := dnsPool{prepare: func(ctx context.Context, address string, _ CaptureConfig) (aliasBinding, error) {
		if calls.Add(1) == 1 {
			started <- address
			<-ctx.Done()
			// A platform call can finish just as Stop is pressed. The pool
			// must release this successful-but-cancelled preparation too.
			return alias, nil
		}
		return &fakeAliasBinding{done: make(chan struct{})}, nil
	}}
	t.Cleanup(pool.close)
	result := make(chan error, 1)
	go func() {
		b, err := pool.acquireContext(ctx, aliasTestConfig("cancelled"))
		if b != nil {
			b.release()
		}
		result <- err
	}()
	address := <-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled setup succeeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS preparation ignored cancellation")
	}
	select {
	case <-alias.done:
	default:
		t.Fatal("cancelled setup retained its alias controller")
	}
	if conn, err := net.DialTimeout("tcp4", address, time.Second); err == nil {
		conn.Close()
		t.Fatal("cancelled setup retained its DNS listener")
	}
	b, err := pool.acquireContext(context.Background(), aliasTestConfig("cancelled"))
	if err != nil {
		t.Fatal("cancelled preparation poisoned VPN generation", err)
	}
	b.release()
	if calls.Load() != 2 {
		t.Fatal("preparation was not retried")
	}
}

func TestDNSCommittedLeaseIndependentOfLaunchCancellation(t *testing.T) {
	pool := dnsPool{prepare: func(context.Context, string, CaptureConfig) (aliasBinding, error) {
		return &fakeAliasBinding{done: make(chan struct{})}, nil
	}}
	t.Cleanup(pool.close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := aliasTestConfig("shared")
	one, err := pool.acquireContext(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	one.release()
	two, err := pool.acquireContext(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer two.release()
	if one.alias != two.alias || one.address != two.address {
		t.Fatal("stopping first software changed the VPN DNS identity")
	}
	for _, done := range []<-chan struct{}{two.done, two.alias.Done()} {
		select {
		case <-done:
			t.Fatal("stopping first software cancelled the shared lease")
		default:
		}
	}
}

func TestDNSPendingWaiterCanCancelAndPoolCloseCancelsPreparation(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int32
	pool := dnsPool{prepare: func(ctx context.Context, _ string, _ CaptureConfig) (aliasBinding, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	config := aliasTestConfig("pending")
	first := make(chan error, 1)
	go func() { _, err := pool.acquireContext(context.Background(), config); first <- err }()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second := make(chan error, 1)
	go func() { _, err := pool.acquireContext(ctx, config); second <- err }()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter blocked on pool lock instead of respecting cancellation")
	}
	closed := make(chan struct{})
	go func() { pool.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("pool close did not cancel preparation")
	}
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("waiter started a competing helper")
	}
	if _, err := pool.acquire(config); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed pool accepted a launch", err)
	}
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
