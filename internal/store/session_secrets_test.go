package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type unavailableSecrets struct{ *MemorySecrets }

func (unavailableSecrets) Set(string, string) error { return errors.New("locked") }

func TestSessionSecretsDoesNotResurrectOldPassword(t *testing.T) {
	primary := NewMemorySecrets()
	_ = primary.Set("account", "old")
	s := NewSessionSecrets(unavailableSecrets{primary})
	// The write is reported as "not persisted" rather than silently accepted:
	// the UI has to tell the user the password will be gone after a restart.
	if err := s.Set("account", "new"); !errors.Is(err, ErrSecretNotPersisted) {
		t.Fatalf("Set error = %v, want ErrSecretNotPersisted", err)
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

// A working credential store must not report ErrSecretNotPersisted.
func TestSessionSecretsReportsPersistedWrites(t *testing.T) {
	primary := NewMemorySecrets()
	s := NewSessionSecrets(primary)
	if err := s.Set("account", "value"); err != nil {
		t.Fatalf("Set on a working store = %v", err)
	}
	if v, err := primary.Get("account"); err != nil || v != "value" {
		t.Fatalf("primary = %q, %v", v, err)
	}
}

// A LAN listener without credentials would be an open relay. Loading such a
// configuration falls back to loopback and says why.
func TestLANListenerWithoutPasswordFallsBackOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	old := `{"version":1,"settings":{"listenHost":"0.0.0.0","aggregateEnabled":true},"points":[]}`
	if err := writeFileAtomic(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, warnings, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.ListenHost != "127.0.0.1" {
		t.Fatalf("listen host = %q, want loopback", cfg.Settings.ListenHost)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "0.0.0.0") {
		t.Fatalf("warnings = %v", warnings)
	}

	// With a password the same address is kept: the user asked for LAN access.
	withPassword := `{"version":1,"settings":{"listenHost":"0.0.0.0","proxyUsername":"hub","proxyPassword":"0123456789abcdef01234567","aggregateEnabled":true},"points":[]}`
	if err := writeFileAtomic(path, []byte(withPassword), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, warnings, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.ListenHost != "0.0.0.0" || len(warnings) != 0 {
		t.Fatalf("host = %q, warnings = %v", cfg.Settings.ListenHost, warnings)
	}

	// A password too short for the LAN rule is treated as no password at all:
	// loading must not hand a weak listener to the LAN just because the field is
	// non-empty.
	short := `{"version":1,"settings":{"listenHost":"0.0.0.0","proxyPassword":"short","aggregateEnabled":true},"points":[]}`
	if err := writeFileAtomic(path, []byte(short), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, warnings, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Settings.ListenHost != "127.0.0.1" || len(warnings) != 1 {
		t.Fatalf("short password: host = %q, warnings = %v", cfg.Settings.ListenHost, warnings)
	}
}
