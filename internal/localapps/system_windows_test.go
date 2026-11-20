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
	if s.fail {
		return nil, errors.New("rules failed")
	}
	return func() error { s.stops.Add(1); return nil }, nil
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
