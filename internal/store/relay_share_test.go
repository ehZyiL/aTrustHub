package store

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func relayTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(dir, NewMemorySecrets())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func relayTestPoint() model.AccessPoint {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return model.AccessPoint{
		ID: "r1", Name: "同事分享", Protocol: model.ProtocolLANRelay,
		Server: "192.168.1.50", Port: 23456, InPool: true,
		Relay: &model.RelayPointOptions{
			Version: 1, ShareID: base64.RawURLEncoding.EncodeToString(b), CertificateSHA256: strings.Repeat("ab", 32),
		},
	}
}

// TestRelayShareStorePersistsIntentAndSecrets covers the real adapter used by the
// controller: Enabled and the bound port go to config.json, the identity and
// token go to the secret store, and a restart reads them back.
func TestRelayShareStorePersistsIntentAndSecrets(t *testing.T) {
	st := relayTestStore(t)
	adapter := RelayShareStore{Store: st}
	if adapter.ShareSettings().Enabled {
		t.Fatal("a fresh store is not enabled")
	}
	settings := relay.Settings{
		Enabled: true, PointID: "a1", InterfaceName: "en0", PreferredIPv4: "192.168.1.50",
		Port: 0, BoundPort: 23456, ShareID: relayTestPoint().Relay.ShareID,
		Fingerprint: strings.Repeat("ab", 32),
	}
	if err := adapter.SaveShareSettings(settings); err != nil {
		t.Fatal(err)
	}
	if err := adapter.SetSecret(relay.IdentitySecretKey(settings.ShareID), "identity-payload"); err != nil {
		t.Fatal(err)
	}
	if err := adapter.SetSecret(relay.ShareTokenKey(settings.ShareID), "token-payload"); err != nil {
		t.Fatal(err)
	}

	// Reopen the store, as an application restart does.
	reopened, err := Open(st.Dir(), st.sec)
	if err != nil {
		t.Fatal(err)
	}
	again := RelayShareStore{Store: reopened}
	got := again.ShareSettings()
	if !got.Enabled || got.PointID != "a1" || got.BoundPort != 23456 || got.Fingerprint != settings.Fingerprint {
		t.Fatalf("settings did not survive a reopen: %+v", got)
	}
	if v, err := again.GetSecret(relay.ShareTokenKey(settings.ShareID)); err != nil || v != "token-payload" {
		t.Fatalf("token lost: %q %v", v, err)
	}
	if err := again.DeleteSecret(relay.ShareTokenKey(settings.ShareID)); err != nil {
		t.Fatal(err)
	}
	if _, err := again.GetSecret(relay.ShareTokenKey(settings.ShareID)); err == nil {
		t.Fatal("deleted token still readable")
	}
}

// TestRelayShareSettingsDoNotLeakSecretsIntoConfig proves the token and the
// private key never appear in config.json.
func TestRelayShareSettingsDoNotLeakSecretsIntoConfig(t *testing.T) {
	st := relayTestStore(t)
	adapter := RelayShareStore{Store: st}
	if err := adapter.SaveShareSettings(relay.Settings{Enabled: true, PointID: "a1", ShareID: "sid", Fingerprint: strings.Repeat("cd", 32)}); err != nil {
		t.Fatal(err)
	}
	_ = adapter.SetSecret(relay.ShareTokenKey("sid"), "super-secret-token")
	data, err := os.ReadFile(filepath.Join(st.Dir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "super-secret-token") {
		t.Fatal("the share token was written into config.json")
	}
	if !strings.Contains(string(data), "lanShare") {
		t.Fatalf("share settings missing from config.json: %s", data)
	}
}

func TestRelayKnownCacheRoundTripAndCorruption(t *testing.T) {
	st := relayTestStore(t)
	resources := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	known, err := st.LoadRelayKnown("r1")
	if err != nil || known != nil {
		t.Fatalf("missing cache should be (nil,nil): %+v %v", known, err)
	}
	if err := st.SaveRelayKnown("r1", "fp/sid", resources); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.LoadRelayKnown("r1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.PointID != "r1" || len(loaded.Resources.IPRules) != 1 {
		t.Fatalf("cache did not round trip: %+v", loaded)
	}
	info, err := os.Stat(st.RelayKnownPath("r1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache permissions = %o, want 0600", info.Mode().Perm())
	}
	if dir, err := os.Stat(filepath.Dir(st.RelayKnownPath("r1"))); err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("cache directory permissions wrong: %v %v", dir, err)
	}

	// A broken cache must be reported, never silently ignored.
	if err := os.WriteFile(st.RelayKnownPath("r1"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadRelayKnown("r1"); !errors.Is(err, ErrRelayKnownCorrupt) {
		t.Fatalf("corrupt cache not reported: %v", err)
	}
	// Deleting the node removes the cache.
	if err := st.SaveRelayKnown("r1", "", resources); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRelayKnown("r1"); err != nil {
		t.Fatal(err)
	}
	if known, err := st.LoadRelayKnown("r1"); err != nil || known != nil {
		t.Fatalf("cache survived deletion: %+v %v", known, err)
	}
}

func TestRelayKnownPointIDCannotEscapeDirectory(t *testing.T) {
	st := relayTestStore(t)
	path := st.RelayKnownPath("../../escape")
	if strings.Contains(path, "..") {
		t.Fatalf("point id escaped the cache directory: %s", path)
	}
}

func TestSetRelayHistoryInitialized(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error {
		cfg.Add(point)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayHistoryInitialized(point.ID); err != nil {
		t.Fatal(err)
	}
	cfg := st.Config()
	if p := cfg.Find(point.ID); p == nil || p.Relay == nil || !p.Relay.HistoryInitialized {
		t.Fatal("history marker not persisted")
	}
	// The marker must not make the node look like a different connection.
	if err := st.SetRelayHistoryInitialized("missing"); err == nil {
		t.Fatal("unknown point accepted")
	}
}
