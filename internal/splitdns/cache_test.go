package splitdns

import (
	"context"
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestCacheScopeTTLAndRetiredSession(t *testing.T) {
	var cache Cache
	id := Identity{GatewayID: "A", Generation: 1, Version: "v1", Mode: "raw"}
	q := new(dns.Msg).SetQuestion("app.test.", dns.TypeA)
	packet, _ := q.Pack()
	calls := 0
	current := true
	exchange := func(_ context.Context, packet []byte) ([]byte, error) {
		calls++
		query := new(dns.Msg)
		query.Unpack(packet)
		m := new(dns.Msg).SetReply(query)
		rr, _ := dns.NewRR("app.test. 30 IN A 10.0.0.8")
		m.Answer = []dns.RR{rr}
		return m.Pack()
	}
	query := func(identity Identity) []byte {
		t.Helper()
		reply, err := cache.Exchange(context.Background(), identity, packet, func() bool { return current }, exchange)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	query(id)
	q.Id++
	packet, _ = q.Pack()
	reply := query(id)
	m := new(dns.Msg)
	m.Unpack(reply)
	if calls != 1 || m.Id != q.Id {
		t.Fatal("cache did not restore query identity")
	}
	for key, e := range cache.entries {
		e.at = e.at.Add(-5 * time.Second)
		cache.entries[key] = e
	}
	m.Unpack(query(id))
	if m.Answer[0].Header().Ttl > 25 {
		t.Fatal("cache extended DNS lifetime")
	}
	other := id
	other.GatewayID = "B"
	query(other)
	other = id
	other.Generation++
	query(other)
	other = id
	other.Version = "v2"
	query(other)
	other = id
	other.Mode = "mapped"
	query(other)
	query(other)
	q.Question[0].Qtype = dns.TypeAAAA
	packet, _ = q.Pack()
	query(id)
	q.Question[0].Qclass = dns.ClassCHAOS
	packet, _ = q.Pack()
	query(id)
	if calls != 8 {
		t.Fatalf("queries=%d", calls)
	}
	current = false
	if _, err := cache.Exchange(context.Background(), id, packet, func() bool { return current }, exchange); err == nil {
		t.Fatal("retired cache hit")
	}
}

func TestCacheDoesNotStoreFailureOrZeroTTL(t *testing.T) {
	for _, code := range []int{dns.RcodeServerFailure, dns.RcodeNameError, dns.RcodeSuccess} {
		var cache Cache
		calls := 0
		q := new(dns.Msg).SetQuestion("missing.test.", dns.TypeA)
		packet, _ := q.Pack()
		for range 2 {
			reply, err := cache.Exchange(context.Background(), Identity{Mode: "raw"}, packet, func() bool { return true }, func(context.Context, []byte) ([]byte, error) {
				calls++
				m := new(dns.Msg).SetRcode(q, code)
				if code == dns.RcodeSuccess {
					rr, _ := dns.NewRR("missing.test. 0 IN A 10.0.0.8")
					m.Answer = []dns.RR{rr}
				}
				return m.Pack()
			})
			if err != nil {
				t.Fatal(err)
			}
			m := new(dns.Msg)
			m.Unpack(reply)
			if m.Rcode != code {
				t.Fatal("changed RCODE")
			}
		}
		if calls != 2 {
			t.Fatal("cached failure or zero TTL")
		}
	}
}
