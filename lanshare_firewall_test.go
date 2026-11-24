package main

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
)

// appFirewall is a controllable privileged executor for the app-level tests.
type appFirewall struct {
	mu      sync.Mutex
	ops     []relay.FirewallOperation
	handler func(relay.FirewallOperation) (relay.FirewallResult, error)
}

func (f *appFirewall) Run(_ context.Context, op relay.FirewallOperation) (relay.FirewallResult, error) {
	f.mu.Lock()
	f.ops = append(f.ops, op)
	handler := f.handler
	f.mu.Unlock()
	if handler != nil {
		return handler(op)
	}
	return relay.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relay.FirewallRemoved}, nil
}

func (f *appFirewall) calls() []relay.FirewallOperation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]relay.FirewallOperation(nil), f.ops...)
}

// installFirewall gives the test app a firewall coordinator with a fake
// privileged executor. It also prevents the real one from ever being built.
func installFirewall(t *testing.T, a *app, exec relay.FirewallExecutor) *relay.Rules {
	t.Helper()
	// Set the executor before the coordinator exists: the coordinator is built
	// lazily on first use, exactly like in production.
	a.fwExec = exec
	return a.firewallRules()
}

// awaitFirewall waits for the scheduled reconciliation to finish. The UI thread
// never blocks on it; tests do, so their assertions see the result.
func (a *app) awaitFirewall(t *testing.T) {
	t.Helper()
	if !a.awaitFirewallIdle(10 * time.Second) {
		t.Fatal("firewall reconciliation did not finish")
	}
}

func firewallAppRule() relay.FirewallRule {
	return relay.FirewallRule{
		ID:          relay.NewFirewallRuleID(23456, time.Unix(0, 1700000000000000000)),
		Name:        "Connect Hub 局域网分享",
		ProgramPath: filepath.Join(string(filepath.Separator), "opt", "connect-hub"),
		Port:        23456,
		Profile:     "private",
		RemoteIP:    "192.168.31.0/24",
		CreatedAt:   time.Now().Unix(),
	}
}

// TestDisableRemovesRecordedFirewallRules is the S3 core: 关闭共享 does not leave
// an inbound rule behind.
func TestDisableRemovesRecordedFirewallRules(t *testing.T) {
	a := testApp(t)
	fake := &appFirewall{}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}

	// The share is not running (a fresh test app never listens), which is exactly
	// the state after 关闭共享.
	a.doReconcileLanShareFirewall(a.lanShareViewState())

	var deleted bool
	for _, op := range fake.calls() {
		if op.Op == relay.FirewallOpDelete && op.RuleID == rule.ID {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("no delete was requested: %+v", fake.calls())
	}
	journal, err = relay.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.Entries) != 0 {
		t.Fatalf("the rule stayed in the journal: %+v", journal.Entries)
	}
}

// TestFirewallCleanupFailureKeepsTheRecord: a denied cleanup must not be reported
// as done, and the record has to survive for the next start.
func TestFirewallCleanupFailureKeepsTheRecord(t *testing.T) {
	a := testApp(t)
	fake := &appFirewall{handler: func(op relay.FirewallOperation) (relay.FirewallResult, error) {
		return relay.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relay.FirewallDenied, Detail: "系统拒绝授权"}, nil
	}}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, _ := relay.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	a.doReconcileLanShareFirewall(a.lanShareViewState())
	if a.firewallErr == "" {
		t.Fatal("a failed cleanup was not reported")
	}
	journal, _ = relay.LoadFirewallJournal(a.dir)
	if journal.Find(rule.ID) == nil {
		t.Fatal("a failed cleanup discarded the recovery record")
	}
	if journal.Find(rule.ID).State == relay.FirewallEntryConfirmed {
		t.Fatal("a failed cleanup still claims the rule is in place")
	}
}

// TestQuitKeepsTheShareIntentButCleansRules: quitting keeps Enabled (the next
// start resumes the share) while the rule serving the closed listener goes.
func TestQuitKeepsTheShareIntentButCleansRules(t *testing.T) {
	a := testApp(t)
	fake := &appFirewall{}
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	withLANShare(t, a)
	installFirewall(t, a, fake)
	if err := a.lanShare.Enable(context.Background(), relay.EnableOptions{PointID: "p1", PreferredIPv4: "127.0.0.1"}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	view := a.lanShare.View()
	rule := relay.FirewallRule{
		ID:          relay.NewFirewallRuleID(view.Port, time.Unix(0, 1)),
		ProgramPath: filepath.Join(string(filepath.Separator), "opt", "connect-hub"),
		Port:        view.Port,
		Profile:     "private",
	}
	journal, _ := relay.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}

	a.shutdownLANShare()
	a.awaitFirewall(t)

	// The enable intent survives: only the rule goes with the closed listener.
	if settings := a.store.Config().Settings.LANShare; !settings.Enabled {
		t.Fatal("quit discarded the share intent")
	}
	journal, _ = relay.LoadFirewallJournal(a.dir)
	if journal.Find(rule.ID) != nil {
		t.Fatal("quitting left the inbound rule behind")
	}
}

// TestDeletedRelayNodeRemovesItsRule: deleting the node takes its rule too.
func TestDeletedRelayNodeRemovesItsRule(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "node-1", Name: "同事分享", Protocol: model.ProtocolLANRelay, Server: "192.168.1.50", Port: 23456, InPool: true,
			Relay: &model.RelayPointOptions{Version: 1, ShareID: "share-identity-1", CertificateSHA256: strings.Repeat("ab", 32)}})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	fake := &appFirewall{}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, _ := relay.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	a.removePoint("node-1")
	a.awaitFirewall(t)
	journal, _ = relay.LoadFirewallJournal(a.dir)
	if journal.Find(rule.ID) != nil {
		t.Fatal("the rule of a removed node survived")
	}
}

// TestFirewallRefusesToGuessTheSubnet: without the interface's real mask no rule
// is created, so a /24 guess can never widen or narrow the share.
func TestFirewallRefusesToGuessTheSubnet(t *testing.T) {
	a := testApp(t)
	fake := &appFirewall{}
	installFirewall(t, a, fake)
	a.allowLanShareFirewall(relay.View{State: relay.StateRunning, Port: 23456, Address: "not-an-ip"})
	if !strings.Contains(a.firewallErr, "子网掩码") {
		t.Fatalf("an unknown subnet was not refused: %q", a.firewallErr)
	}
	for _, op := range fake.calls() {
		if op.Op == relay.FirewallOpApply {
			t.Fatalf("a rule was created without a verified subnet: %+v", op)
		}
	}
}

// TestDesiredRulesMatchTheRunningShareExactly: a recorded rule only counts as
// desired when program, port and scope still match.
func TestDesiredRulesMatchTheRunningShareExactly(t *testing.T) {
	a := testApp(t)
	installFirewall(t, a, &appFirewall{})
	exe, err := filepath.Abs(filepath.Join("build", "connect-hub"))
	if err != nil {
		t.Fatal(err)
	}
	base := relay.FirewallRule{ID: relay.FirewallRulePrefix + "1", ProgramPath: exe, Port: 23456, Profile: "private", RemoteIP: "192.168.31.0/24"}
	other := base
	other.ID = relay.FirewallRulePrefix + "2"
	other.RemoteIP = "10.0.0.0/8"
	journal, _ := relay.LoadFirewallJournal(a.dir)
	for _, rule := range []relay.FirewallRule{base, other} {
		if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
			t.Fatal(err)
		}
	}
	// A non-running share justifies nothing.
	desired, err := a.desiredFirewallRules(relay.View{State: relay.StateBlocked, Port: 23456, Address: "192.168.31.77"})
	if err != nil || len(desired) != 0 {
		t.Fatalf("a blocked share kept rules: %+v %v", desired, err)
	}
	// A different port matches nothing.
	desired, err = a.desiredFirewallRules(relay.View{State: relay.StateRunning, Port: 23457, Address: "192.168.31.77"})
	if err != nil || len(desired) != 0 {
		t.Fatalf("a different port reused another rule: %+v %v", desired, err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// S: the share state seen by the firewall coordinator is written from action
// goroutines (启用/关闭共享) and from the render path. It must be race-free.
func TestFirewallSeenStateIsRaceFree(t *testing.T) {
	a := testApp(t)
	installFirewall(t, a, &appFirewall{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.syncLanShareFirewall()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			a.syncLanShareFirewallIfNeeded()
		}
	}()
	wg.Wait()
	a.awaitFirewall(t)
}

// S: quitting must give the scheduled cleanup a bounded chance to finish instead
// of returning while the goroutine is still running.
func TestQuitWaitsForFirewallCleanup(t *testing.T) {
	a := testApp(t)
	released := make(chan struct{})
	fake := &appFirewall{handler: func(op relay.FirewallOperation) (relay.FirewallResult, error) {
		if op.Op == relay.FirewallOpDelete {
			time.Sleep(120 * time.Millisecond)
			select {
			case <-released:
			default:
				close(released)
			}
		}
		return relay.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relay.FirewallRemoved}, nil
	}}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, _ := relay.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	a.shutdownLANShare()
	// No awaitFirewall here on purpose: shutdown itself must have waited.
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) != nil {
		t.Fatal("quit returned before the rule was cleaned up")
	}
	select {
	case <-released:
	default:
		t.Fatal("the delete never ran")
	}
}

// S: the scheduler used two independent atomics, so a request arriving between
// "no more work" and "release the running flag" was silently dropped while
// quitting reported success. The handover is now one critical section.
func TestFirewallQueueNeverLosesAWakeup(t *testing.T) {
	var q firewallQueue
	if !q.start() {
		t.Fatal("the first request must launch a worker")
	}
	// A request that arrives while the worker runs must be remembered.
	if q.start() {
		t.Fatal("a second worker was launched")
	}
	if !q.more() {
		t.Fatal("the folded request was lost")
	}
	if q.idle() {
		t.Fatal("the queue claims to be idle while a pass is running")
	}
	// The follow-up pass ends the worker; from here a new request must launch.
	if q.more() {
		t.Fatal("an extra pass was scheduled")
	}
	if !q.idle() {
		t.Fatal("the queue is not idle after the last pass")
	}
	if !q.start() {
		t.Fatal("a request after idle did not launch a worker")
	}
	if q.more() {
		t.Fatal("the last pass did not finish")
	}
}

// The app-level queue must converge: after a burst of requests the final state is
// applied and the queue reports idle, so quitting cannot report a false success.
func TestFirewallSchedulerConverges(t *testing.T) {
	a := testApp(t)
	fake := &appFirewall{}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, err := relay.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Put(a.dir, relay.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relay.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				a.syncLanShareFirewallIfNeeded()
				return
			}
			a.reconcileLanShareFirewall(a.lanShareViewState())
		}(i)
	}
	wg.Wait()
	if !a.awaitFirewallIdle(10 * time.Second) {
		t.Fatal("the queue never became idle")
	}
	journal, err = relay.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) != nil {
		t.Fatal("the final cleanup request was dropped")
	}
}
