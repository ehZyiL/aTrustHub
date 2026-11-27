package desktop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
	"github.com/ehzyil/connect-hub/internal/store"
	"github.com/ehzyil/connect-hub/internal/vpn"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

type fakePairAttempt struct {
	updates chan relay.PairProgress
	acked   atomic.Bool
	closed  atomic.Bool
	ack     func() error
	stored  func() error
	success bool
}

func (f *fakePairAttempt) Updates() <-chan relay.PairProgress { return f.updates }
func (f *fakePairAttempt) Stored(context.Context) error {
	if f.stored != nil {
		return f.stored()
	}
	return nil
}
func (f *fakePairAttempt) Close() error { f.closed.Store(true); return nil }
func (f *fakePairAttempt) Ack(context.Context) error {
	if f.ack != nil {
		if err := f.ack(); err != nil {
			return err
		}
	}
	f.acked.Store(true)
	if f.success {
		return nil
	}
	return errors.New("injected ack response loss")
}

func TestPairCheckpointUIStorageRetryAndConfirmedGrantProtection(t *testing.T) {
	a := testApp(t)
	code, _ := relay.ParseShareCode(sampleShareCode())
	code.Version = 2
	attempt := &fakePairAttempt{updates: make(chan relay.PairProgress, 1)}
	a.relayImport = relayImportDraft{open: true, pairAttempt: attempt}
	receipts := 0
	attempt.stored = func() error {
		id := a.relayImport.pairStoredID
		secret, err := a.store.Password(id)
		cfg := a.store.Config()
		if id == "" || err != nil || secret != code.Token || cfg.Find(id) == nil {
			return errors.New("storage receipt preceded durable checkpoint")
		}
		receipts++
		return nil
	}
	attempt.updates <- relay.PairProgress{Request: relay.PairRequest{State: "saving"}, Code: &code}
	a.drainPairImport()
	if receipts != 1 || a.relayImport.err != "" {
		t.Fatal("checkpoint not acknowledged after storage", a.relayImport.err)
	}
	id := a.relayImport.pairStoredID
	// A rejected/timed-out attempt is retried with a fresh private key on the
	// same unconfirmed node. The existing node ID and manager attribution stay.
	a.relayImport.pairStoredID = ""
	code.Token = "replacement-private-seed"
	if err := a.persistPairImport(code); err != nil {
		t.Fatal(err)
	}
	secret, _ := a.store.Password(id)
	if a.relayImport.pairStoredID != id || secret != code.Token || len(a.store.Config().Points) != 1 {
		t.Fatal("retry reused old credential or duplicated node")
	}
	_, _ = a.store.Update(func(cfg *model.Config) error { cfg.Find(id).Relay.PairingUnconfirmed = false; return nil })
	a.setConfig(a.store.Config())
	a.relayImport.pairStoredID = ""
	code.Token = "must-not-replace-confirmed-key"
	if err := a.persistPairImport(code); err == nil {
		t.Fatal("confirmed credential silently overwritten")
	}
	if saved, _ := a.store.Password(id); saved != secret {
		t.Fatal("failed retry altered confirmed credential")
	}
	a.stopPairImport()
}

type unavailablePairSecrets struct{ *store.MemorySecrets }

func (unavailablePairSecrets) Set(string, string) error {
	return errors.New("injected secret store failure")
}

func TestPairCheckpointUIFailureCannotSendStorageReceipt(t *testing.T) {
	for _, failure := range []string{"secret", "config"} {
		t.Run(failure, func(t *testing.T) {
			a := testApp(t)
			code, _ := relay.ParseShareCode(sampleShareCode())
			code.Version = 2
			if failure == "secret" {
				var err error
				a.store, err = store.Open(t.TempDir(), unavailablePairSecrets{store.NewMemorySecrets()})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(a.store.Dir(), "config.json")
				if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			a.setConfig(a.store.Config())
			attempt := &fakePairAttempt{updates: make(chan relay.PairProgress, 1), stored: func() error { t.Error("failed checkpoint sent receipt"); return nil }}
			a.relayImport = relayImportDraft{open: true, pairAttempt: attempt}
			attempt.updates <- relay.PairProgress{Request: relay.PairRequest{State: "saving"}, Code: &code}
			a.drainPairImport()
			if a.relayImport.err == "" || a.relayImport.pairStoredID != "" || len(a.store.Config().Points) != 0 {
				t.Fatal("checkpoint failure retained node or hid error")
			}
		})
	}
}

func TestPairClaimUIReceiptCompletesAndStartsConnection(t *testing.T) {
	a := testApp(t)
	code, _ := relay.ParseShareCode(sampleShareCode())
	code.Version = 2
	attempt := &fakePairAttempt{updates: make(chan relay.PairProgress, 1), success: true}
	a.relayImport = relayImportDraft{open: true, pairAttempt: attempt, pairProgress: relay.PairProgress{Request: relay.PairRequest{State: "approved"}, Code: &code}}
	a.claimPairImport()
	id := a.relayImport.pairStoredID
	deadline := time.Now().Add(2 * time.Second)
	for a.relayImport.open && time.Now().Before(deadline) {
		a.drainPairImport()
		time.Sleep(time.Millisecond)
	}
	if a.relayImport.open || a.relayImport.err != "" || !strings.Contains(a.toast, "正在连接") {
		t.Fatal("claim did not close dialog and initiate connection", a.relayImport.err)
	}
	cfg := a.store.Config()
	if p := cfg.Find(id); p == nil || p.Relay.PairingUnconfirmed {
		t.Fatal("confirmed receipt marker was not persisted")
	}
}

func TestPairCancelledClaimCannotFinishNewTab(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "failure"}[success], func(t *testing.T) {
			a := testApp(t)
			code, _ := relay.ParseShareCode(sampleShareCode())
			code.Version = 2
			entered, release := make(chan struct{}), make(chan struct{})
			attempt := &fakePairAttempt{updates: make(chan relay.PairProgress, 1), success: success, ack: func() error { close(entered); <-release; return nil }}
			a.relayImport = relayImportDraft{open: true, tab: 2, pairAttempt: attempt, pairProgress: relay.PairProgress{Request: relay.PairRequest{State: "approved"}, Code: &code}}
			a.claimPairImport()
			<-entered
			ack := a.relayImport.pairAck
			id := a.relayImport.pairStoredID
			a.stopPairImport()
			a.relayImport.tab = 1
			close(release)
			deadline := time.Now().Add(time.Second)
			for len(ack) == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if len(ack) == 0 {
				t.Fatal("ack did not complete")
			}
			a.drainPairImport()
			if !a.relayImport.open || a.relayImport.tab != 1 || a.toast != "" || a.relayImport.err != "" {
				t.Fatalf("cancelled claim changed current UI: open=%v toast=%q err=%q", a.relayImport.open, a.toast, a.relayImport.err)
			}
			cfg := a.store.Config()
			if p := cfg.Find(id); p == nil || !p.Relay.PairingUnconfirmed {
				t.Fatal("cancel lost or confirmed checkpoint")
			}
		})
	}
}

func TestPairCancelledClaimCannotAffectReopenedOrNewAttempt(t *testing.T) {
	for _, next := range []string{"reopen", "new-attempt"} {
		for _, success := range []bool{true, false} {
			t.Run(next+map[bool]string{true: "/success", false: "/failure"}[success], func(t *testing.T) {
				a := testApp(t)
				code, _ := relay.ParseShareCode(sampleShareCode())
				code.Version = 2
				entered, release := make(chan struct{}), make(chan struct{})
				old := &fakePairAttempt{updates: make(chan relay.PairProgress, 1), success: success, ack: func() error { close(entered); <-release; return nil }}
				a.relayImport = relayImportDraft{open: true, tab: 2, pairAttempt: old, pairProgress: relay.PairProgress{Request: relay.PairRequest{State: "approved"}, Code: &code}}
				a.claimPairImport()
				<-entered
				ack, id := a.relayImport.pairAck, a.relayImport.pairStoredID
				a.closeRelayImport()
				a.openRelayImport()
				var current *fakePairAttempt
				if next == "new-attempt" {
					current = &fakePairAttempt{updates: make(chan relay.PairProgress, 1)}
					a.pairStart = func(context.Context, relay.PairTarget, string) (relay.PairAttempt, error) { return current, nil }
					a.relayImport.tab, a.relayImport.pin = 2, "12345678"
					a.beginPairImport()
					waitPairUI(t, a, func() bool { return a.relayImport.pairAttempt == current })
				}
				a.relayImport.err = "current-dialog"
				close(release)
				waitPairUI(t, a, func() bool { return len(ack) == 1 })
				a.drainPairImport()
				wrongAttempt := current != nil && a.relayImport.pairAttempt != current || current == nil && a.relayImport.pairAttempt != nil
				if !a.relayImport.open || a.toast != "" || a.relayImport.err != "current-dialog" || wrongAttempt {
					t.Fatal("old receipt affected reopened dialog")
				}
				cfg := a.store.Config()
				if p := cfg.Find(id); p == nil || !p.Relay.PairingUnconfirmed {
					t.Fatal("stored checkpoint lost or confirmed after cancel")
				}
				if secret, err := a.store.Password(id); err != nil || secret != code.Token {
					t.Fatal("saved credential lost")
				}
				a.stopPairImport()
			})
		}
	}
}

func waitPairUI(t *testing.T, a *app, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() && time.Now().Before(deadline) {
		a.drainPairImport()
		time.Sleep(time.Millisecond)
	}
	if !ready() {
		t.Fatal("pair UI condition did not complete")
	}
}

func TestPairLateStartCannotReplaceCurrentAttempt(t *testing.T) {
	for _, success := range []bool{true, false} {
		for _, timing := range []string{"buffered-before-stop", "returned-after-stop"} {
			t.Run(map[bool]string{true: "success/", false: "failure/"}[success]+timing, func(t *testing.T) {
				a := testApp(t)
				entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
				old := &fakePairAttempt{updates: make(chan relay.PairProgress, 1)}
				current := &fakePairAttempt{updates: make(chan relay.PairProgress, 1)}
				a.pairStart = func(context.Context, relay.PairTarget, string) (relay.PairAttempt, error) {
					close(entered)
					<-release
					defer close(returned)
					if success {
						return old, nil
					}
					return nil, errors.New("old-start-error")
				}
				a.relayImport = relayImportDraft{open: true, tab: 2, pin: "12345678"}
				a.beginPairImport()
				<-entered
				mailbox := a.relayImport.pairStarts
				if timing == "buffered-before-stop" {
					close(release)
					deadline := time.Now().Add(time.Second)
					for len(mailbox) == 0 && time.Now().Before(deadline) {
						time.Sleep(time.Millisecond)
					}
					if len(mailbox) == 0 {
						t.Fatal("start result not buffered")
					}
				}
				a.stopPairImport()
				a.pairStart = func(context.Context, relay.PairTarget, string) (relay.PairAttempt, error) { return current, nil }
				a.relayImport.pin = "87654321"
				a.beginPairImport()
				waitPairUI(t, a, func() bool { return a.relayImport.pairAttempt == current })
				current.updates <- relay.PairProgress{Request: relay.PairRequest{ID: "current", State: "pending"}}
				a.drainPairImport()
				if timing == "returned-after-stop" {
					close(release)
				}
				<-returned
				if success {
					waitPairUI(t, a, func() bool { return old.closed.Load() })
				}
				a.drainPairImport()
				if a.relayImport.pairAttempt != current || a.relayImport.pairProgress.Request.ID != "current" || a.relayImport.err != "" || !a.relayImport.open {
					t.Fatal("late start replaced current UI")
				}
				a.stopPairImport()
			})
		}
	}
}

func TestPairLostReceiptSuccessfulSnapshotConfirmsStoredDevice(t *testing.T) {
	a := testApp(t)
	code, _ := relay.ParseShareCode(sampleShareCode())
	code.Version = 2
	if err := a.persistPairImport(code); err != nil {
		t.Fatal(err)
	}
	id := a.relayImport.pairStoredID
	// Also exercise a later reconnect with an already initialized history.
	_, _ = a.store.Update(func(cfg *model.Config) error { cfg.Find(id).Relay.HistoryInitialized = true; return nil })
	if err := a.saveRelaySnapshot(id, vpn.RelaySnapshotSource{ShareID: code.ShareID, Fingerprint: code.Fingerprint}, &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3"}); err != nil {
		t.Fatal(err)
	}
	cfg := a.store.Config()
	if cfg.Find(id).Relay.PairingUnconfirmed || !a.cfgReload.Load() {
		t.Fatal("authenticated reconnect left device replaceable")
	}
}

func TestPairingUIStateAndIndependentDeviceControls(t *testing.T) {
	a := testApp(t)
	withLANShare(t, a)
	a.openLANShare()
	a.lanShareUI.pairAt = time.Now()
	a.lanShareUI.pair = relay.PairView{Invitation: &relay.Invitation{ID: "invite", ExpiresAt: time.Now().Add(time.Minute), Capacity: 5, Approved: 2}, Requests: []relay.PairRequest{{ID: "request", Name: "same name", DeviceID: strings.Repeat("a", 64), Verification: "abc123", State: "pending", Source: "192.168.1.2"}}, Devices: []relay.PairedDevice{{ID: strings.Repeat("b", 64), Name: "saved device"}}}
	a.lanShareUI.pairPIN = "12345678"
	view := func(c *ui.Context) {
		a.pairingManageView(c, relay.View{Enabled: true, State: relay.StateRunning, Pairing: true})
	}
	texts := strings.Join(ui.NewTester(view, 900, 900).Texts(), "|")
	for _, want := range []string{"12345678", "剩余名额 3/5", "abc123", "same name", "saved device", "暂停共享", "无法单独识别或撤销"} {
		if !strings.Contains(texts, want) {
			t.Fatalf("missing %q in %s", want, texts)
		}
	}
}

func TestPairClaimStoresPrivateKeyBeforeAckAndKeepsItOnLoss(t *testing.T) {
	a := testApp(t)
	code, err := relay.ParseShareCode(sampleShareCode())
	if err != nil {
		t.Fatal(err)
	}
	code.Version = 2
	attempt := &fakePairAttempt{updates: make(chan relay.PairProgress, 1)}
	a.relayImport = relayImportDraft{open: true, tab: 2, pairAttempt: attempt, pairProgress: relay.PairProgress{Request: relay.PairRequest{State: "approved"}, Code: &code}}
	attempt.ack = func() error {
		cfg := a.store.Config()
		for _, p := range cfg.Points {
			if p.Relay != nil && p.Relay.Version == 2 && p.Relay.ShareID == code.ShareID {
				secret, err := a.store.Password(p.ID)
				if err != nil || secret != code.Token {
					return errors.New("private key not saved before ack")
				}
				if p.Relay.CertificateSHA256 != code.Fingerprint {
					return errors.New("host identity missing")
				}
				return nil
			}
		}
		return errors.New("point not persisted")
	}
	a.claimPairImport()
	deadline := time.Now().Add(2 * time.Second)
	for !attempt.acked.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !attempt.acked.Load() {
		t.Fatal("ack happened before persistence or did not run")
	}
	a.drainPairImport()
	if a.relayImport.pairStoredID == "" || !strings.Contains(a.relayImport.err, "设备已安全保存") {
		t.Fatal("lost ack did not retain recoverable device", a.relayImport.err)
	}
	if strings.Contains(a.relayImport.err, code.Token) {
		t.Fatal("error leaked private key")
	}
	a.stopPairImport()
}

func TestDiscoveryPairingEntryAndExplicitLegacyEntry(t *testing.T) {
	for _, pairing := range []bool{false, true} {
		t.Run(map[bool]string{false: "v1", true: "v2"}[pairing], func(t *testing.T) {
			a := testApp(t)
			cand := discovery.Candidate{DraftVersion: 1, ProtocolVersion: 1, ShareID: "test", Address: "192.168.1.5", Port: 12345, Pairing: pairing}
			tester := ui.NewTester(func(c *ui.Context) { a.relayDiscoveryAction(c, &a.relayImport, cand) }, 900, 500)
			if err := tester.Click("加入"); err != nil {
				t.Fatal("join unavailable")
			}
			want := 1
			if pairing {
				want = 2
			}
			if a.relayImport.tab != want {
				t.Fatalf("tab=%d want=%d", a.relayImport.tab, want)
			}
			if a.relayImport.parsed {
				t.Fatal("discovery granted trust")
			}
		})
	}
}
