package localapps

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

type selectedAlias struct {
	*fakeAliasBinding
	queries atomic.Int32
	onQuery func()
}

func (a *selectedAlias) Exchange(_ context.Context, packet []byte) ([]byte, error) {
	a.queries.Add(1)
	if a.onQuery != nil {
		a.onQuery()
	}
	q := new(dns.Msg)
	if err := q.Unpack(packet); err != nil {
		return nil, err
	}
	return new(dns.Msg).SetReply(q).Pack()
}

func TestSharedDNSUsesSelectedInstalledPublisherAndRejectsLateResult(t *testing.T) {
	a := &selectedAlias{fakeAliasBinding: &fakeAliasBinding{done: make(chan struct{})}}
	b := &selectedAlias{fakeAliasBinding: &fakeAliasBinding{done: make(chan struct{})}}
	p := &dnsPool{entries: map[string]*dnsEntry{"A": {alias: a}, "B": {alias: b}}}
	current := true
	selected := "B"
	selector := func([]byte) (string, func() bool, error) {
		if selected == "conflict" {
			return "", nil, errors.New("conflict")
		}
		return selected, func() bool { return current }, nil
	}
	q, _ := new(dns.Msg).SetQuestion("db.corp.test.", dns.TypeA).Pack()
	if _, err := p.exchangeSelected(context.Background(), selector, q); err != nil {
		t.Fatal(err)
	}
	if a.queries.Load() != 0 || b.queries.Load() != 1 {
		t.Fatal("shared DNS broadcast or crossed ownership")
	}
	selected = "conflict"
	if _, err := p.exchangeSelected(context.Background(), selector, q); err == nil {
		t.Fatal("conflict accepted")
	}
	selected = "absent"
	if _, err := p.exchangeSelected(context.Background(), selector, q); err == nil {
		t.Fatal("missing publisher triggered fallback")
	}
	selected = "B"
	b.onQuery = func() { current = false }
	if _, err := p.exchangeSelected(context.Background(), selector, q); err == nil {
		t.Fatal("late DNS result survived policy change")
	}
	if a.queries.Load() != 0 || b.queries.Load() != 2 {
		t.Fatal("failure retried another gateway")
	}
}
