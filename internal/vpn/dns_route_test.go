package vpn

import (
	"context"
	"errors"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/splitdns"
	"github.com/ehzyil/connect-hub/internal/workeripc"
	"github.com/miekg/dns"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestMappedDNSSelectionSharesProductionOwnershipAndGeneration(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.info.Resources = &workeripc.ResourceSnapshot{InternalDomains: []string{"a.test"}}
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	packet, _ := new(dns.Msg).SetQuestion("b.test.", dns.TypeA).Pack()
	key, current, err := m.SelectMappedDNS(packet)
	if err != nil || !current() {
		t.Fatal(key, err)
	}
	connection, err := m.LocalAppConnection("B")
	if err != nil || connection.Key != key {
		t.Fatal("selector bypassed shared generation identity", key, err)
	}
	m.mu.Lock()
	m.points["B"].gen++
	m.mu.Unlock()
	if current() {
		t.Fatal("old selection survived generation change")
	}
	m.Disconnect("B")
	if _, _, err := m.SelectMappedDNS(packet); err == nil {
		t.Fatal("offline owner fell back")
	}
}

type routeDNSSession struct {
	*routeSession
	queries  atomic.Int32
	exchange func(context.Context, []byte) ([]byte, error)
}

func TestEquivalentDNSNewQueryChangesSessionOnlyAfterPrimaryOffline(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	settings := model.DefaultSettings()
	settings.SharedExits = []routing.Group{{ID: "same-service", Pattern: "b.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Gateways: []string{"A", "B"}, DNSFailover: true}}
	m := routeTestManager(t, settings, a, b)
	da, db := &routeDNSSession{routeSession: a}, &routeDNSSession{routeSession: b}
	m.mu.Lock()
	m.points["A"].sess, m.points["B"].sess = da, db
	m.mu.Unlock()
	q, _ := new(dns.Msg).SetQuestion("b.test.", dns.TypeA).Pack()
	keyA, validA, err := m.SelectMappedDNS(q)
	if err != nil || !validA() {
		t.Fatal(keyA, err)
	}
	if _, err = m.ExchangeResourceDNS(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if da.queries.Load() != 1 || db.queries.Load() != 0 {
		t.Fatal("query was broadcast")
	}
	m.Disconnect("A")
	keyB, validB, err := m.SelectMappedDNS(q)
	if err != nil || !validB() || keyA == keyB || validA() {
		t.Fatal("backup reused the old mapped session identity", keyA, keyB, err)
	}
	if _, err = m.ExchangeResourceDNS(context.Background(), q); err != nil || db.queries.Load() != 1 {
		t.Fatal("backup reused another gateway cache", err, db.queries.Load())
	}
	backup, err := m.LocalAppConnection("B")
	if err != nil {
		t.Fatal(err)
	}
	finish, err := backup.BeginPublication("198.19.16.0/20")
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	aliases := []workeripc.DNSAlias{{Address: "198.19.16.1", Original: "10.0.0.8", TTL: 60}}
	if err = m.mappings.Stage(backup.Key, "b.test", aliases); err != nil {
		t.Fatal(err)
	}
	if err = backup.ConfirmAliases(aliases); err != nil {
		t.Fatal(err)
	}
	newA := &routeDNSSession{routeSession: routeTestSession("A"), exchange: func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("DNS timeout")
	}}
	m.mu.Lock()
	ep := m.points["A"]
	ep.gen++
	ep.state, ep.sess, ep.info = StateOnline, newA, cloneSessionInfo(newA.Info())
	m.mu.Unlock()
	if validB() {
		t.Fatal("previous backup selection remained valid after primary recovery")
	}
	if _, err = m.ExchangeResourceDNS(context.Background(), q); err == nil || newA.queries.Load() != 1 || db.queries.Load() != 1 {
		t.Fatal("timeout was hidden by retrying another DNS gateway", err)
	}
	ctx := WithOriginalDial(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		t.Error("mapped DNS fell back to the original network")
		return nil, net.ErrClosed
	})
	conn, err := m.DialCaptured(ctx, "tcp", "198.19.16.1:443")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	conn.Close()
	if err != nil || string(body) != "B" || newA.strictCalls.Load() != 0 {
		t.Fatal("published backup identity changed on primary recovery", string(body), err)
	}
	m.Disconnect("B")
	if _, err = m.DialCaptured(ctx, "tcp", "198.19.16.1:443"); err == nil || newA.strictCalls.Load() != 0 {
		t.Fatal("offline backup alias was rebound to the primary")
	}
	m.mu.Lock()
	m.settings.SharedExits[0].DNSFailover = false
	m.mu.Unlock()
	if _, _, err = m.SelectMappedDNS(q); err == nil {
		t.Fatal("disabled DNS sharing continued to resolve ambiguous names")
	}
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
