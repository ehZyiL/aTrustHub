package localapps

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qy/easyconnect/internal/dnsmapping"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/vpn"
	"github.com/qy/easyconnect/internal/wincapture"
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
