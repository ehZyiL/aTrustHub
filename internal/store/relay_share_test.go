package store

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	source := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256, Label: "fp/sid"}
	resources := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	known, err := st.LoadRelayKnown("r1")
	if err != nil || known != nil {
		t.Fatalf("missing cache should be (nil,nil): %+v %v", known, err)
	}
	if _, err := st.SaveRelayKnown("r1", source, resources); err != nil {
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
	if _, err := st.SaveRelayKnown("r1", source, resources); err != nil {
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

// R2: the cache was replaced by the newest snapshot, so a target that the
// sharing host withdrew disappeared from the history and later became an
// ordinary direct connection.
func TestRelayKnownKeepsWithdrawnHistory(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	source := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	full := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
		DomainRules: []workeripc.DomainRule{
			{Domain: "git.corp.example", PortMin: 22, PortMax: 22, Protocol: "tcp"},
		},
	}
	if _, err := st.SaveRelayKnown(point.ID, source, full); err != nil {
		t.Fatal(err)
	}
	// The host withdraws everything: an empty snapshot must not erase history.
	if _, err := st.SaveRelayKnown(point.ID, source, &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"}); err != nil {
		t.Fatal(err)
	}
	known, err := st.LoadRelayKnown(point.ID)
	if err != nil {
		t.Fatal(err)
	}
	if known == nil || len(known.Resources.IPRules) != 1 || len(known.Resources.DomainRules) != 1 {
		t.Fatalf("withdrawn history was dropped: %+v", known)
	}
	// Re-saving the same snapshot must not grow the cache.
	for i := 0; i < 5; i++ {
		if _, err := st.SaveRelayKnown(point.ID, source, full); err != nil {
			t.Fatal(err)
		}
	}
	if known, err = st.LoadRelayKnown(point.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(known.Resources.IPRules) + len(known.Resources.DomainRules); n != 2 {
		t.Fatalf("repeated snapshots duplicated entries: %d", n)
	}
}

// R2: saves of the same node must not lose each other's history.
func TestRelayKnownConcurrentSavesKeepEveryRule(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	source := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			snap := &workeripc.ResourceSnapshot{
				Tunnel:  "ipv4-l3",
				IPRules: []workeripc.IPRule{{Min: fmt.Sprintf("10.%d.0.0", w), Max: fmt.Sprintf("10.%d.255.255", w), PortMin: 443, PortMax: 443, Protocol: "tcp"}},
			}
			if _, err := st.SaveRelayKnown(point.ID, source, snap); err != nil {
				t.Errorf("save %d: %v", w, err)
			}
		}(w)
	}
	wg.Wait()
	known, err := st.LoadRelayKnown(point.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(known.Resources.IPRules); got != workers {
		t.Fatalf("concurrent saves lost history: %d of %d rules survived", got, workers)
	}
}

// R2: a snapshot from a share the node no longer has must be refused, so a late
// callback cannot rebuild the cache after a re-import or a delete.
func TestRelayKnownRefusesStaleSource(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	snap := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	good := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	if _, err := st.SaveRelayKnown(point.ID, good, snap); err != nil {
		t.Fatal(err)
	}
	// A different share id or fingerprint is a different node identity.
	other := RelaySource{ShareID: strings.Repeat("z", 22), Fingerprint: strings.Repeat("cd", 32)}
	if _, err := st.SaveRelayKnown(point.ID, other, snap); !errors.Is(err, ErrRelayKnownStaleSource) {
		t.Fatalf("a snapshot from another share was accepted: %v", err)
	}
	// Deleting the node invalidates a session that is still running.
	if err := st.DeleteRelayKnown(point.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Update(func(cfg *model.Config) error {
		cfg.Remove(point.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRelayKnown(point.ID, good, snap); !errors.Is(err, ErrRelayKnownStaleSource) {
		t.Fatalf("a snapshot recreated the cache of a deleted node: %v", err)
	}
	if known, err := st.LoadRelayKnown(point.ID); err != nil || known != nil {
		t.Fatalf("a deleted node got its cache back: %+v %v", known, err)
	}
}

// R2: the 4 MiB bound is enforced, and a broken cache must not stop a verified
// snapshot from being stored.
func TestRelayKnownBoundsAndCorruptCacheBehavior(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	source := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}

	// A cache that no longer parses keeps its evidence but does not block a new
	// verified snapshot: refusing would also lose the history we still have.
	if err := os.MkdirAll(filepath.Dir(st.RelayKnownPath(point.ID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.RelayKnownPath(point.ID), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := st.LoadRelayKnown(point.ID); !errors.Is(err, ErrRelayKnownCorrupt) {
		t.Fatalf("a corrupt cache was not reported: %v", err)
	}
	small := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.7.0.0", Max: "10.7.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	if _, err := st.SaveRelayKnown(point.ID, source, small); err != nil {
		t.Fatalf("a corrupt cache blocked a verified snapshot: %v", err)
	}
	known, err := st.LoadRelayKnown(point.ID)
	if err != nil || known == nil || len(known.Resources.IPRules) != 1 {
		t.Fatalf("the repaired cache did not round trip: %+v %v", known, err)
	}

	// An oversized merge is refused and leaves the stored file intact.
	huge := &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"}
	for i := 0; i < 40000; i++ {
		huge.IPRules = append(huge.IPRules, workeripc.IPRule{
			Min: fmt.Sprintf("10.%d.%d.0", i/256%256, i%256), Max: fmt.Sprintf("10.%d.%d.255", i/256%256, i%256),
			PortMin: 443, PortMax: 443, Protocol: "tcp",
		})
	}
	if _, err := st.SaveRelayKnown(point.ID, source, huge); err == nil {
		t.Fatal("an oversized history was accepted")
	}
	known, err = st.LoadRelayKnown(point.ID)
	if err != nil || known == nil || len(known.Resources.IPRules) != 1 {
		t.Fatalf("a refused save damaged the existing cache: %+v %v", known, err)
	}
}

// S: a corrupt cache must not be silently "repaired" by the next snapshot. The
// loss is persisted so the protection gate stays on until the user decides.
func TestRelayKnownCorruptionIsPersistedAsIncomplete(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	source := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	full := &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	}
	if _, err := st.SaveRelayKnown(point.ID, source, full); err != nil {
		t.Fatal(err)
	}
	if err := st.SetRelayHistoryInitialized(point.ID); err != nil {
		t.Fatal(err)
	}

	// The cache is damaged outside the app.
	if err := os.WriteFile(st.RelayKnownPath(point.ID), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The next verified snapshot cannot prove what the lost history owned.
	write, err := st.SaveRelayKnown(point.ID, source, &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"})
	if err != nil {
		t.Fatal(err)
	}
	if !write.Incomplete {
		t.Fatal("a save over a corrupt cache was reported as complete history")
	}
	known, err := st.LoadRelayKnown(point.ID)
	if err != nil {
		t.Fatal(err)
	}
	if known == nil || !known.Incomplete {
		t.Fatalf("the incompleteness was not persisted: %+v", known)
	}
	// It stays incomplete across further snapshots: only recovery or the user can
	// clear it.
	write, err = st.SaveRelayKnown(point.ID, source, full)
	if err != nil {
		t.Fatal(err)
	}
	if !write.Incomplete {
		t.Fatal("a later snapshot silently cleared the incomplete history")
	}
	// The explicit user decision clears it.
	if err := st.ClearRelayKnownIncomplete(point.ID); err != nil {
		t.Fatal(err)
	}
	known, err = st.LoadRelayKnown(point.ID)
	if err != nil {
		t.Fatal(err)
	}
	if known.Incomplete {
		t.Fatal("clearing the protection did not persist")
	}
	// History itself is still a union; clearing the mark does not forget rules.
	if len(known.Resources.IPRules) != 1 {
		t.Fatalf("clearing the mark changed the stored history: %+v", known.Resources)
	}
}

// A missing cache for a node that was already initialised is also a loss.
func TestRelayKnownMissingAfterInitialisationIsIncomplete(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	source := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	// First run: nothing stored yet, so the snapshot is the whole truth.
	write, err := st.SaveRelayKnown(point.ID, source, &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"})
	if err != nil {
		t.Fatal(err)
	}
	if write.Incomplete {
		t.Fatal("a first snapshot was marked incomplete")
	}
	if err := st.SetRelayHistoryInitialized(point.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRelayKnown(point.ID); err != nil {
		t.Fatal(err)
	}
	// Second run: the node had history and the cache is gone.
	write, err = st.SaveRelayKnown(point.ID, source, &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"})
	if err != nil {
		t.Fatal(err)
	}
	if !write.Incomplete {
		t.Fatal("a lost cache was treated as a first snapshot")
	}
}

// The explicit release must also persist when the cache is unreadable, otherwise
// the user could never get out of the protected state.
func TestClearRelayKnownIncompleteWorksOnACorruptCache(t *testing.T) {
	st := relayTestStore(t)
	point := relayTestPoint()
	if _, err := st.Update(func(cfg *model.Config) error { cfg.Add(point); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(st.RelayKnownPath(point.ID)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(st.RelayKnownPath(point.ID), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearRelayKnownIncomplete(point.ID); err != nil {
		t.Fatalf("clearing a corrupt cache failed: %v", err)
	}
	known, err := st.LoadRelayKnown(point.ID)
	if err != nil {
		t.Fatalf("the released cache is still unreadable: %v", err)
	}
	if known == nil || known.Incomplete {
		t.Fatalf("the release did not persist: %+v", known)
	}
	// A later verified snapshot extends the empty history instead of marking it
	// incomplete again.
	src := RelaySource{ShareID: point.Relay.ShareID, Fingerprint: point.Relay.CertificateSHA256}
	write, err := st.SaveRelayKnown(point.ID, src, &workeripc.ResourceSnapshot{
		Tunnel:  "ipv4-l3",
		IPRules: []workeripc.IPRule{{Min: "10.5.0.0", Max: "10.5.255.255", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if write.Incomplete {
		t.Fatal("the release was undone by the next snapshot")
	}
}
