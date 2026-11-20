package localapps

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/workeripc"
	"sync/atomic"
	"testing"
)

type diagnosticPublisher struct {
	published atomic.Int32
	fail      bool
}

func (p *diagnosticPublisher) Prefix() string { return "198.19.0.0/20" }
func (p *diagnosticPublisher) Publish(context.Context, []workeripc.DNSAlias) error {
	p.published.Add(1)
	if p.fail {
		return errors.New("publish failed")
	}
	return nil
}

type diagnosticBinding struct {
	*fakeAliasBinding
	pub    *diagnosticPublisher
	config CaptureConfig
}

func (b *diagnosticBinding) Exchange(ctx context.Context, packet []byte) ([]byte, error) {
	return exchangeMappedDNS(ctx, b.pub, b.config, packet)
}

func TestDiagnosticUsesRunningPublicationChainAndNeverStartsCapture(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	q := new(dns.Msg).SetQuestion("corp.test.", dns.TypeA)
	packet, _ := q.Pack()
	if _, err := m.ExchangeRunningMappedDNS(context.Background(), "session", packet); err == nil {
		t.Fatal("diagnostic started an absent runtime")
	}
	var prepared, confirmed atomic.Int32
	var publications atomic.Int32
	pub := &diagnosticPublisher{}
	config := CaptureConfig{Key: "session", Domains: []string{"corp.test"}, Active: func() bool { return true }, MappedDNS: func(_ context.Context, packet []byte, prefix string) (workeripc.Message, error) {
		q := new(dns.Msg)
		q.Unpack(packet)
		reply := new(dns.Msg).SetReply(q)
		rr, _ := dns.NewRR("corp.test. 60 IN A 198.19.0.1")
		reply.Answer = []dns.RR{rr}
		answer, _ := reply.Pack()
		return workeripc.Message{DNS: answer, DNSAliases: []workeripc.DNSAlias{{Address: "198.19.0.1", Original: "10.0.0.8", TTL: 60}}}, nil
	}, ConfirmAliases: func([]workeripc.DNSAlias) error {
		if pub.published.Load() == 0 {
			t.Error("confirmed before platform install")
		}
		confirmed.Add(1)
		return nil
	}}
	config.BeginPublication = func(string) (func(), error) { publications.Add(1); return func() { publications.Add(-1) }, nil }
	m.dns.prepare = func(_ context.Context, _ string, c CaptureConfig) (aliasBinding, error) {
		prepared.Add(1)
		return &diagnosticBinding{fakeAliasBinding: &fakeAliasBinding{done: make(chan struct{})}, pub: pub, config: c}, nil
	}
	binding, err := m.dns.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.release()
	answer, err := m.ExchangeRunningMappedDNS(context.Background(), "session", packet)
	if err != nil {
		t.Fatal(err)
	}
	reply := new(dns.Msg)
	reply.Unpack(answer)
	if reply.Rcode != dns.RcodeSuccess || confirmed.Load() != 1 || prepared.Load() != 1 || publications.Load() != 0 {
		t.Fatal("diagnostic bypassed live publication")
	}
	pub.fail = true
	answer, err = m.ExchangeRunningMappedDNS(context.Background(), "session", packet)
	if err != nil {
		t.Fatal(err)
	}
	reply.Unpack(answer)
	if reply.Rcode != dns.RcodeServerFailure || confirmed.Load() != 1 {
		t.Fatal("failed publication returned synthetic answer")
	}
}
