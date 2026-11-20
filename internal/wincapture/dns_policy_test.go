package wincapture

import (
	"errors"
	"slices"
	"testing"
)

func TestDNSPolicyUnionAndRollbackPreserveExistingScope(t *testing.T) {
	var actual []string
	failAfterWrite := false
	writes := 0
	p := &dnsPolicy{apply: func(before, after []string) error {
		if slices.Equal(actual, after) {
			return nil
		}
		if !slices.Equal(actual, before) {
			return errors.New("external change")
		}
		actual = slices.Clone(after)
		writes++
		if failAfterWrite {
			failAfterWrite = false
			return errors.New("confirmation failed")
		}
		return nil
	}}
	a, err := p.acquire("A", []string{"corp.test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.acquire("B", []string{"corp.test", "db.corp.test"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actual, []string{"corp.test", "db.corp.test"}) {
		t.Fatal(actual)
	}
	failAfterWrite = true
	if _, err := p.acquire("C", []string{"c.test"}); err == nil {
		t.Fatal("failed DNS confirmation accepted")
	}
	if p.dirty || !slices.Equal(actual, []string{"corp.test", "db.corp.test"}) {
		t.Fatal("failed C changed A/B", actual)
	}
	if err := b(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(actual, []string{"corp.test"}) {
		t.Fatal("B removed A namespace", actual)
	}
	if err := b(); err != nil {
		t.Fatal(err)
	}
	if err := a(); err != nil {
		t.Fatal(err)
	}
	if len(actual) != 0 || writes != 6 {
		t.Fatal("wrong delta writes", actual, writes)
	}
}

func TestDNSPolicyRetainsFailedRollbackAndRefusesNewChanges(t *testing.T) {
	fail := true
	p := &dnsPolicy{apply: func([]string, []string) error {
		if fail {
			return errors.New("OS unavailable")
		}
		return nil
	}}
	rollback, err := p.acquire("A", []string{"corp.test"})
	if err == nil || rollback == nil || !p.dirty {
		t.Fatal("failed rollback forgotten")
	}
	if _, err := p.acquire("B", []string{"b.test"}); err == nil {
		t.Fatal("dirty DNS accepted another scope")
	}
	fail = false
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.acquire("B", []string{"b.test"}); err != nil {
		t.Fatal(err)
	}
}
