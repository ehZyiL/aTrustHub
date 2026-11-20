package vpn

import (
	"context"
	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/routing"
	"github.com/qy/easyconnect/internal/workeripc"
	"testing"
)

type mappedTestSession struct{ *routeSession }

func (s *mappedTestSession) ExchangeMappedDNS(ctx context.Context, packet []byte, prefix string) (workeripc.Message, error) {
	q := new(dns.Msg)
	q.Unpack(packet)
	m := new(dns.Msg).SetReply(q)
	rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 198.19.0.1")
	m.Answer = []dns.RR{rr}
	answer, _ := m.Pack()
	return workeripc.Message{DNS: answer, DNSAliases: []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.0.0.8", TTL: 60}}}, nil
}

func TestSoftwareLeasesShareMappedIdentityAfterPublication(t *testing.T) {
	s := routeTestSession("B")
	m := routeTestManager(t, model.DefaultSettings(), s)
	m.mu.Lock()
	m.points["B"].sess = &mappedTestSession{s}
	m.mu.Unlock()
	one, err := m.LocalAppConnection("B")
	if err != nil {
		t.Fatal(err)
	}
	two, err := m.LocalAppConnection("B")
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := new(dns.Msg).SetQuestion("b.test.", dns.TypeA).Pack()
	reply, err := one.MappedDNS(context.Background(), packet, "198.19.0.0/20")
	if err != nil {
		t.Fatal(err)
	}
	if c, e := two.Dial(context.Background(), "tcp", "198.19.0.1:443"); e == nil {
		c.Close()
		t.Fatal("unpublished alias dialed")
	}
	if err = one.ConfirmAliases(reply.DNSAliases); err != nil {
		t.Fatal(err)
	}
	c, err := two.Dial(context.Background(), "tcp", "198.19.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	m.mu.Lock()
	m.settings.RoutePolicies = []routing.Policy{{ID: "deny", Pattern: "b.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Action: "block"}}
	m.mu.Unlock()
	if c, e := two.Dial(context.Background(), "tcp", "198.19.0.1:443"); e == nil {
		c.Close()
		t.Fatal("mapped request bypassed original-domain policy")
	}
	m.Disconnect("B")
	if err = one.ConfirmAliases(reply.DNSAliases); err == nil {
		t.Fatal("published after session ended")
	}
}
