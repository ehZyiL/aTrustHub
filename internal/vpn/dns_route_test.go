package vpn

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/routing"
	"github.com/qy/easyconnect/internal/splitdns"
	"github.com/qy/easyconnect/internal/workeripc"
	"sync/atomic"
	"testing"
	"time"
)

type routeDNSSession struct {
	*routeSession
	queries  atomic.Int32
	exchange func(context.Context, []byte) ([]byte, error)
}

func (s *routeDNSSession) ExchangeDNS(ctx context.Context, packet []byte) ([]byte, error) {
	s.queries.Add(1)
	if s.exchange != nil {
		return s.exchange(ctx, packet)
	}
	q := new(dns.Msg)
	q.Unpack(packet)
	m := new(dns.Msg).SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 30 IN A 10.0.0.8")
	m.Answer = []dns.RR{rr}
	return m.Pack()
}

func TestResourceDNSTransportsSelectOwnerCacheAndFailClosed(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.info.Resources = &workeripc.ResourceSnapshot{InternalDomains: []string{"a.test"}}
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	da, db := &routeDNSSession{routeSession: a}, &routeDNSSession{routeSession: b}
	m.mu.Lock()
	m.points["A"].sess = da
	m.points["B"].sess = db
	m.mu.Unlock()
	server, err := splitdns.Listen(context.Background(), m.ExchangeResourceDNS)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, network := range []string{"udp", "tcp"} {
		q := new(dns.Msg).SetQuestion("b.test.", dns.TypeA)
		reply, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(q, server.Addr())
		if err != nil || reply.Rcode != dns.RcodeSuccess {
			t.Fatalf("%v %v", reply, err)
		}
	}
	if da.queries.Load() != 0 || db.queries.Load() != 1 {
		t.Fatal("DNS broadcast or cache crossed identity")
	}
	m.mu.Lock()
	m.points["B"].gen++
	m.mu.Unlock()
	q := new(dns.Msg).SetQuestion("b.test.", dns.TypeA)
	packet, _ := q.Pack()
	if _, err = m.ExchangeResourceDNS(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	if db.queries.Load() != 2 {
		t.Fatal("new generation reused old answer")
	}
	db.exchange = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("gateway timeout") }
	m.mu.Lock()
	m.points["B"].gen++
	m.mu.Unlock()
	reply, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(q, server.Addr())
	if err != nil || reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("timeout was not SERVFAIL: %v %v", reply, err)
	}
	m.Disconnect("B")
	answer, err := m.ExchangeResourceDNS(context.Background(), packet)
	if err != nil {
		t.Fatal(err)
	}
	reply.Unpack(answer)
	if reply.Rcode != dns.RcodeServerFailure || da.queries.Load() != 0 {
		t.Fatal("offline owner escaped")
	}
}

func TestDNSConflictAndLateReply(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	entered, release := make(chan struct{}), make(chan struct{})
	db := &routeDNSSession{routeSession: b, exchange: func(_ context.Context, packet []byte) ([]byte, error) {
		close(entered)
		<-release
		q := new(dns.Msg)
		q.Unpack(packet)
		return new(dns.Msg).SetReply(q).Pack()
	}}
	m.mu.Lock()
	m.points["B"].sess = db
	m.mu.Unlock()
	q := new(dns.Msg).SetQuestion("b.test.", dns.TypeA)
	packet, _ := q.Pack()
	answer, err := m.ExchangeResourceDNS(context.Background(), packet)
	if err != nil {
		t.Fatal(err)
	}
	reply := new(dns.Msg)
	reply.Unpack(answer)
	if reply.Rcode != dns.RcodeServerFailure || db.queries.Load() != 0 {
		t.Fatal("ambiguous DNS queried a gateway")
	}
	m.mu.Lock()
	m.settings.DNSBindings = []routing.DNSBinding{{ID: "default", Pattern: "b.test", GatewayID: "B"}}
	m.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, e := m.ExchangeResourceDNS(context.Background(), packet); done <- e }()
	<-entered
	m.mu.Lock()
	m.points["B"].gen++
	m.mu.Unlock()
	close(release)
	if err = <-done; err == nil {
		t.Fatal("old generation DNS reply accepted")
	}
}
