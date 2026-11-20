package wincapture

import (
	"errors"
	"testing"
)

func TestSharedRuleRollbackPreservesOtherSessionAndFailedCleanup(t *testing.T) {
	shared := sharedRules{}
	installed, removed := 0, 0
	failCleanup := false
	install := func() (func() error, error) {
		installed++
		return func() error {
			if failCleanup {
				return errors.New("busy")
			}
			removed++
			return nil
		}, nil
	}
	a, err := shared.acquire("route", install)
	if err != nil {
		t.Fatal(err)
	}
	b := ruleSet{install: []func() (func() error, error){
		func() (func() error, error) { return shared.acquire("route", install) },
		func() (func() error, error) { return nil, errors.New("DNS conflict") },
	}}
	if err = b.Enable(); err == nil {
		t.Fatal("expected failure")
	}
	if installed != 1 || removed != 0 || shared["route"].refs != 1 {
		t.Fatal("B rollback removed A route")
	}
	failCleanup = true
	if err := a(); err == nil {
		t.Fatal("failed cleanup lost")
	}
	if _, err := shared.acquire("route", install); err == nil {
		t.Fatal("pending cleanup treated as healthy")
	}
	failCleanup = false
	if err := a(); err != nil {
		t.Fatal(err)
	}
	if err := a(); err != nil {
		t.Fatal(err)
	}
	if removed != 1 || len(shared) != 0 {
		t.Fatal("cleanup not idempotent")
	}
}
