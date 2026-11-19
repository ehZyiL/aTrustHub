package store

import (
	"errors"
	"testing"
)

type unavailableSecrets struct{ *MemorySecrets }

func (unavailableSecrets) Set(string, string) error { return errors.New("locked") }

func TestSessionSecretsDoesNotResurrectOldPassword(t *testing.T) {
	primary := NewMemorySecrets()
	_ = primary.Set("account", "old")
	s := NewSessionSecrets(unavailableSecrets{primary})
	if err := s.Set("account", "new"); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get("account")
	if err != nil || got != "new" {
		t.Fatal("stale primary value replaced session credential")
	}
	_ = s.Delete("account")
	if _, err = s.Get("account"); !errors.Is(err, ErrSecretNotFound) {
		t.Fatal(err)
	}
}
