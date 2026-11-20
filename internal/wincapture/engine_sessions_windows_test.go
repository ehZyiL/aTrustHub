package wincapture

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/workeripc"
)

func testSessionEngine(t *testing.T) (*engine, map[netip.Prefix]int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	counts := map[netip.Prefix]int{}
	e := &engine{ctx: ctx, cancel: cancel, adapter: netip.MustParsePrefix("198.18.0.0/30"),
		sessions: map[string]*captureSession{}, apps: map[string]*registration{}, shared: sharedRules{}}
	e.installRoute = func(p netip.Prefix) (func() error, error) {
		counts[p]++
		return func() error { counts[p]--; return nil }, nil
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e, counts
}

func TestEngineRegistersSeparatePoolsAndRetiresOnlySelectedGateway(t *testing.T) {
	e, counts := testSessionEngine(t)
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	resource := netip.MustParsePrefix("10.44.0.0/24")
	for i, id := range []string{a, b} {
		prefix := []string{"198.19.0.0/20", "198.19.16.0/20"}[i]
		if err := e.registerPrepared(id, poolTestConfig(id), netip.MustParsePrefix(prefix), []netip.Prefix{resource}, []netip.Addr{netip.MustParseAddr("192.0.2.10")}); err != nil {
			t.Fatal(err)
		}
		if err := e.sessions[id].rules.Enable(); err != nil {
			t.Fatal(err)
		}
		alias := workeripc.DNSAlias{Address: e.sessions[id].aliases.Addr().Next().String(), Original: "10.44.0.8", TTL: 60}
		if err := e.publish(id, []workeripc.DNSAlias{alias}); err != nil {
			t.Fatal(err)
		}
	}
	if counts[resource] != 1 {
		t.Fatal("duplicate OS resource route", counts)
	}
	if err := e.validateAppTarget(a, netip.MustParseAddr("198.19.16.1")); err == nil {
		t.Fatal("A consumed B identity")
	}
	if err := e.publish(a, []workeripc.DNSAlias{{Address: "198.19.16.2", Original: "10.44.0.8", TTL: 60}}); err == nil {
		t.Fatal("A published into B")
	}
	if err := e.unregister(b); err != nil {
		t.Fatal(err)
	}
	if counts[resource] != 1 || e.sessions[a].ctx.Err() != nil {
		t.Fatal("B teardown disturbed A")
	}
	if counts[e.sessions[b].aliases] != 1 {
		t.Fatal("retired pool lost route before TTL")
	}
	if err := e.publish(b, nil); err == nil {
		t.Fatal("late B publish accepted")
	}
	if err := e.validateAppTarget(b, netip.MustParseAddr("198.19.16.1")); err == nil {
		t.Fatal("retired B granted connection")
	}
	if err := e.validateAppTarget(a, netip.MustParseAddr("198.19.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := e.registerPrepared(strings.Repeat("c", 32), poolTestConfig("C"), e.sessions[b].aliases, nil, nil); err == nil {
		t.Fatal("reused retired B address identity")
	}
	if err := e.unregister(a); err != nil {
		t.Fatal(err)
	}
	if counts[resource] != 0 {
		t.Fatal("last resource reference not removed")
	}
}

func TestEngineSessionInstallFailureDoesNotChangeExistingGateway(t *testing.T) {
	e, counts := testSessionEngine(t)
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if err := e.registerPrepared(a, poolTestConfig("A"), netip.MustParsePrefix("198.19.0.0/20"), nil, nil); err != nil {
		t.Fatal(err)
	}
	e.installRoute = func(netip.Prefix) (func() error, error) { return nil, errors.New("OS route failed") }
	if err := e.registerPrepared(b, poolTestConfig("B"), netip.MustParsePrefix("198.19.16.0/20"), nil, nil); err == nil {
		t.Fatal("route failure ignored")
	}
	if len(e.sessions) != 1 || counts[e.sessions[a].aliases] != 1 {
		t.Fatal("failed registration changed A")
	}
}

func testGatewayDNS(t *testing.T, calls *atomic.Int32) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: listener, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		calls.Add(1)
		_ = w.WriteMsg(new(dns.Msg).SetReply(q))
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown(); listener.Close() })
	return listener.Addr().String()
}

func TestRuntimeDNSSelectsOneGatewayAndOfflineDoesNotFallback(t *testing.T) {
	e, _ := testSessionEngine(t)
	var callsA, callsB atomic.Int32
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	for i, item := range []struct{ id, domain, address string }{
		{a, "a.test", testGatewayDNS(t, &callsA)},
		{b, "b.test", testGatewayDNS(t, &callsB)},
	} {
		config := poolTestConfig(item.id)
		config.Domains, config.DNSAddress = []string{item.domain}, item.address
		if err := e.registerPrepared(item.id, config, netip.MustParsePrefix([]string{"198.19.0.0/20", "198.19.16.0/20"}[i]), nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if answer := e.dnsQuery(ctx, new(dns.Msg).SetQuestion("db.b.test.", dns.TypeA)); answer.Rcode != dns.RcodeSuccess {
		t.Fatal(answer)
	}
	if callsA.Load() != 0 || callsB.Load() != 1 {
		t.Fatal("DNS queried wrong gateway")
	}
	if err := e.unregister(b); err != nil {
		t.Fatal(err)
	}
	if answer := e.dnsQuery(ctx, new(dns.Msg).SetQuestion("db.b.test.", dns.TypeA)); answer.Rcode != dns.RcodeServerFailure {
		t.Fatal("offline answer", answer)
	}
	if answer := e.dnsQuery(ctx, new(dns.Msg).SetQuestion("db.a.test.", dns.TypeA)); answer.Rcode != dns.RcodeSuccess {
		t.Fatal("A disrupted", answer)
	}
	if callsA.Load() != 1 || callsB.Load() != 1 {
		t.Fatal("offline DNS fell back")
	}
}
