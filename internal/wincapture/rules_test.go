package wincapture

import (
	"errors"
	"reflect"
	"testing"
)

func TestRulesRollbackAndRetry(t *testing.T) {
	var actions []string
	cleanupFails := true
	installFails := true
	rules := ruleSet{install: []func() (func() error, error){
		func() (func() error, error) {
			actions = append(actions, "route+")
			return func() error {
				actions = append(actions, "route-")
				if cleanupFails {
					return errors.New("busy")
				}
				return nil
			}, nil
		},
		func() (func() error, error) {
			actions = append(actions, "dns+")
			if installFails {
				return nil, errors.New("policy conflict")
			}
			return func() error { actions = append(actions, "dns-"); return nil }, nil
		},
	}}
	if err := rules.Enable(); err == nil {
		t.Fatal("partial install passed")
	}
	if rules.active || len(rules.undo) != 1 {
		t.Fatal("failed rollback lost ownership")
	}
	if err := rules.Enable(); err == nil {
		t.Fatal("enabled with uncleared rules")
	}
	cleanupFails = false
	if err := rules.Disable(); err != nil {
		t.Fatal(err)
	}
	installFails = false
	if err := rules.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := rules.Enable(); err != nil {
		t.Fatal(err)
	}
	if err := rules.Disable(); err != nil {
		t.Fatal(err)
	}
	if err := rules.Disable(); err != nil {
		t.Fatal(err)
	}
	want := []string{"route+", "dns+", "route-", "route-", "route+", "dns+", "dns-", "route-"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("actions=%v", actions)
	}
}

func TestRulesPartialDNSInstallIsRolledBackBeforeRoutes(t *testing.T) {
	var actions []string
	rules := ruleSet{install: []func() (func() error, error){
		func() (func() error, error) {
			return func() error { actions = append(actions, "route-"); return nil }, nil
		},
		func() (func() error, error) {
			return func() error { actions = append(actions, "dns-"); return nil }, errors.New("effective policy verification failed")
		},
	}}
	if err := rules.Enable(); err == nil {
		t.Fatal("partially effective DNS accepted")
	}
	if !reflect.DeepEqual(actions, []string{"dns-", "route-"}) || rules.active || len(rules.undo) != 0 {
		t.Fatalf("partial DNS install was not rolled back: %v", actions)
	}
}
