package localapps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ehzyil/connect-hub/internal/dnsmapping"
	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/proxy"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"github.com/ehzyil/connect-hub/internal/wincapture"
	proxy2 "golang.org/x/net/proxy"
)

type fakeSystemSession struct {
	done                              chan struct{}
	starts, stops, releases, original atomic.Int32
	fail                              bool
	stopFailures                      atomic.Int32
	upstream                          wincapture.Upstream
}

func (s *fakeSystemSession) Done() <-chan struct{} { return s.done }
func (s *fakeSystemSession) Err() error            { return nil }
func (s *fakeSystemSession) OriginalDial(context.Context, string, string) (net.Conn, error) {
	s.original.Add(1)
	return nil, errors.New("original fixture")
}
func (s *fakeSystemSession) EnableSystem(_ context.Context, u wincapture.Upstream) (func() error, error) {
	s.starts.Add(1)
	s.upstream = u
	stop := func() error {
		s.stops.Add(1)
		if s.stopFailures.Add(-1) >= 0 {
			return errors.New("native cleanup failed")
		}
		return nil
	}
	if s.fail {
		return stop, errors.New("rules failed")
	}
	return stop, nil
}
func systemTestConfig(id string) CaptureConfig {
	return CaptureConfig{Key: id, Identity: dnsmapping.Identity{Key: id, GatewayID: id, Generation: 1, Version: "v1"}, Gateway: "vpn.test", Networks: []netpolicy.Range{{Min: "10.44.0.8", Max: "10.44.0.8"}}, Active: func() bool { return true }}
}

func TestSystemCaptureSharesPrivateEntryAndOriginalExit(t *testing.T) {
	sessions := map[string]*fakeSystemSession{"A": {done: make(chan struct{})}, "B": {done: make(chan struct{})}}
	acquire := func(_ context.Context, key string, _ wincapture.Config) (systemSession, func(), error) {
		s := sessions[key]
		return s, func() { s.releases.Add(1) }, nil
	}
	manager := vpn.NewManager(nil, nil, nil, nil)
	defer manager.Close()
	r, err := startSystemCapture(context.Background(), &dnsPool{}, []CaptureConfig{systemTestConfig("A"), systemTestConfig("B")}, manager.DialCaptured, acquire)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if sessions["A"].upstream != sessions["B"].upstream || len(r.scopes) != 2 {
		t.Fatal("system scopes did not share private entry")
	}
	u := sessions["A"].upstream
	dial, _ := proxy.NewSOCKSDialer(u.Address, &proxy2.Auth{User: u.Username, Password: u.Password})
	if _, err := dial.DialContext(context.Background(), "tcp", "192.0.2.80:443"); err == nil || sessions["A"].original.Load() != 1 {
		t.Fatal("system direct bypassed helper egress")
	}
	bad, _ := proxy.NewSOCKSDialer(u.Address, &proxy2.Auth{User: u.Username, Password: strings.Repeat("x", 64)})
	if _, err := bad.DialContext(context.Background(), "tcp", "192.0.2.80:443"); err == nil || sessions["A"].original.Load() != 1 {
		t.Fatal("untrusted caller entered system route")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		if s.stops.Load() != 1 || s.releases.Load() != 1 {
			t.Fatal("scope leaked")
		}
	}
}

func TestSystemCaptureReconcilesRepeatedReconnects(t *testing.T) {
	ctx := context.Background()
	a, b := systemTestConfig("A"), systemTestConfig("B")
	b.Networks = []netpolicy.Range{{Min: "10.45.0.8", Max: "10.45.0.8"}}
	live := map[string]*fakeSystemSession{}
	reject := ""
	var coverageLost bool
	acquire := func(_ context.Context, key string, _ wincapture.Config) (systemSession, func(), error) {
		if key == reject {
			return nil, nil, errors.New("new scope not ready")
		}
		if len(live) >= 3 {
			return nil, nil, errors.New("too many scopes")
		}
		s := &fakeSystemSession{done: make(chan struct{})}
		live[key] = s
		return s, func() {
			delete(live, key)
			if key != a.Key && len(live) == 1 {
				coverageLost = true
			}
			close(s.done)
		}, nil
	}
	r, err := startSystemCapture(ctx, &dnsPool{}, []CaptureConfig{a, b},
		func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }, acquire)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	originalA := live[a.Key]
	for gen := 2; gen <= 33; gen++ {
		guard := b
		guard.Key, guard.Guard = fmt.Sprintf("guard-%d", gen), true
		if err := r.Reconcile(ctx, []CaptureConfig{a, guard}); err != nil || len(live) != 2 {
			t.Fatalf("offline generation %d allocated a redundant guard: %v", gen, err)
		}
		b.Key = fmt.Sprintf("B-%d", gen)
		b.Identity.Generation = gen
		reject = b.Key
		if err := r.Reconcile(ctx, []CaptureConfig{a, b}); err == nil || len(live) != 2 {
			t.Fatalf("failed generation %d lost old coverage: %v", gen, err)
		}
		reject = ""
		if err := r.Reconcile(ctx, []CaptureConfig{a, b}); err != nil || len(live) != 2 || live[b.Key] == nil {
			t.Fatalf("generation %d did not replace its previous scope: %v", gen, err)
		}
	}
	if live[a.Key] != originalA || originalA.stops.Load() != 0 || coverageLost {
		t.Fatal("reconnect interrupted capture coverage")
	}
}

func TestSystemCaptureKeepsOldRoutesWithoutReplacementCoverage(t *testing.T) {
	ctx := context.Background()
	before, after := systemTestConfig("before"), systemTestConfig("after")
	after.Identity.GatewayID = before.Identity.GatewayID
	after.Networks = []netpolicy.Range{{Min: "10.45.0.8", Max: "10.45.0.8"}}
	a := &fakeSystemSession{done: make(chan struct{})}
	b := &fakeSystemSession{done: make(chan struct{})}
	acquire := func(_ context.Context, key string, _ wincapture.Config) (systemSession, func(), error) {
		if key == before.Key {
			return a, func() {}, nil
		}
		return b, func() {}, nil
	}
	r, err := startSystemCapture(ctx, &dnsPool{}, []CaptureConfig{before},
		func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }, acquire)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Reconcile(ctx, []CaptureConfig{after}); err != nil || a.stops.Load() != 0 {
		t.Fatal("previous resource could escape to the original network", err)
	}
}

func TestSystemCapturePartialStartRollsBackAndIPv6FailsBeforeAcquire(t *testing.T) {
	a, b := &fakeSystemSession{done: make(chan struct{})}, &fakeSystemSession{done: make(chan struct{}), fail: true}
	var acquired atomic.Int32
	acquire := func(_ context.Context, key string, _ wincapture.Config) (systemSession, func(), error) {
		acquired.Add(1)
		s := a
		if key == "B" {
			s = b
		}
		return s, func() { s.releases.Add(1) }, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	if _, err := startSystemCapture(context.Background(), &dnsPool{}, []CaptureConfig{systemTestConfig("A"), systemTestConfig("B")}, dial, acquire); err == nil {
		t.Fatal("partial startup accepted")
	}
	if a.stops.Load() != 1 || a.releases.Load() != 1 || b.releases.Load() != 1 {
		t.Fatal("partial rollback leaked scope")
	}
	config := systemTestConfig("C")
	config.Networks = []netpolicy.Range{{Min: "2001:db8::1", Max: "2001:db8::1"}}
	if _, err := startSystemCapture(context.Background(), &dnsPool{}, []CaptureConfig{config}, dial, acquire); err == nil || acquired.Load() != 2 {
		t.Fatal("unsupported IPv6 reached privileged setup")
	}
}

func TestSystemCaptureRetriesOnlyPendingCleanup(t *testing.T) {
	a, b := &fakeSystemSession{done: make(chan struct{})}, &fakeSystemSession{done: make(chan struct{})}
	b.stopFailures.Store(1)
	acquire := func(_ context.Context, key string, _ wincapture.Config) (systemSession, func(), error) {
		s := a
		if key == "B" {
			s = b
		}
		return s, func() { s.releases.Add(1) }, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	r, err := startSystemCapture(context.Background(), &dnsPool{}, []CaptureConfig{systemTestConfig("A"), systemTestConfig("B")}, dial, acquire)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err == nil || r.Err() == nil || a.releases.Load() != 1 || b.releases.Load() != 0 {
		t.Fatal("failed scope lost cleanup capability", err)
	}
	select {
	case <-r.Done():
	default:
		t.Fatal("stopping did not revoke runtime")
	}
	if err := r.Close(); err != nil || r.Err() != nil || a.stops.Load() != 1 || b.stops.Load() != 2 || b.releases.Load() != 1 {
		t.Fatal("cleanup retry did not finish only pending scope", err)
	}
	if err := r.Close(); err != nil || b.stops.Load() != 2 {
		t.Fatal("successful cleanup not idempotent", err)
	}
}

func TestSystemCaptureStartupRetainsFailedRollback(t *testing.T) {
	s := &fakeSystemSession{done: make(chan struct{}), fail: true}
	s.stopFailures.Store(2) // Add rollback and startup rollback both fail.
	acquire := func(context.Context, string, wincapture.Config) (systemSession, func(), error) {
		return s, func() { s.releases.Add(1) }, nil
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	r, err := startSystemCapture(context.Background(), &dnsPool{}, []CaptureConfig{systemTestConfig("A")}, dial, acquire)
	if err == nil || r == nil || s.releases.Load() != 0 {
		t.Fatal("failed startup discarded pending cleanup", err)
	}
	if err := r.Close(); err != nil || s.stops.Load() != 3 || s.releases.Load() != 1 {
		t.Fatal("startup rollback cannot retry", err)
	}
	var manager Manager
	if run, err := manager.StartSystemCapture(context.Background(), nil, dial); err == nil || run != nil {
		t.Fatal("preflight failure returned a typed nil runtime", run, err)
	}
}
