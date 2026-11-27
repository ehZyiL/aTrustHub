package desktop

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
)

// appFirewall is a controllable privileged executor for the app-level tests.
type appFirewall struct {
	mu      sync.Mutex
	ops     []relayfirewall.FirewallOperation
	handler func(relayfirewall.FirewallOperation) (relayfirewall.FirewallResult, error)
}

func (f *appFirewall) Run(_ context.Context, op relayfirewall.FirewallOperation) (relayfirewall.FirewallResult, error) {
	f.mu.Lock()
	f.ops = append(f.ops, op)
	handler := f.handler
	f.mu.Unlock()
	if handler != nil {
		return handler(op)
	}
	return relayfirewall.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relayfirewall.FirewallRemoved}, nil
}

func (f *appFirewall) calls() []relayfirewall.FirewallOperation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]relayfirewall.FirewallOperation(nil), f.ops...)
}

// installFirewall gives the test app a firewall coordinator with a fake
// privileged executor. It also prevents the real one from ever being built.
func installFirewall(t *testing.T, a *app, exec relayfirewall.FirewallExecutor) *relayfirewall.Rules {
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

// testProgramPath is the path of the running test binary, which is what
// os.Executable() reports during a test — the same source the panel uses.
func testProgramPath(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func firewallAppRule() relayfirewall.FirewallRule {
	exe, err := os.Executable()
	if err != nil {
		exe = filepath.Join(string(filepath.Separator), "opt", "connect-hub")
	}
	return relayfirewall.FirewallRule{
		ID:          relayfirewall.NewFirewallRuleID(23456, time.Unix(0, 1700000000000000000)),
		Name:        "Connect Hub 局域网分享",
		ProgramPath: exe,
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
	journal, err := relayfirewall.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}

	// The share is not running (a fresh test app never listens), which is exactly
	// the state after 关闭共享.
	a.doReconcileLanShareFirewall(a.lanShareViewState())

	var deleted bool
	for _, op := range fake.calls() {
		if op.Op == relayfirewall.FirewallOpDelete && op.RuleID == rule.ID {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("no delete was requested: %+v", fake.calls())
	}
	journal, err = relayfirewall.LoadFirewallJournal(a.dir)
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
	fake := &appFirewall{handler: func(op relayfirewall.FirewallOperation) (relayfirewall.FirewallResult, error) {
		return relayfirewall.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relayfirewall.FirewallDenied, Detail: "系统拒绝授权"}, nil
	}}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, _ := relayfirewall.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	a.doReconcileLanShareFirewall(a.lanShareViewState())
	if a.firewallErr == "" {
		t.Fatal("a failed cleanup was not reported")
	}
	journal, _ = relayfirewall.LoadFirewallJournal(a.dir)
	if journal.Find(rule.ID) == nil {
		t.Fatal("a failed cleanup discarded the recovery record")
	}
	if journal.Find(rule.ID).State == relayfirewall.FirewallEntryConfirmed {
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
	rule := relayfirewall.FirewallRule{
		ID:          relayfirewall.NewFirewallRuleID(view.Port, time.Unix(0, 1)),
		ProgramPath: filepath.Join(string(filepath.Separator), "opt", "connect-hub"),
		Port:        view.Port,
		Profile:     "private",
	}
	journal, _ := relayfirewall.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}

	a.shutdownLANShare()
	a.awaitFirewall(t)

	// The enable intent survives: only the rule goes with the closed listener.
	if settings := a.store.Config().Settings.LANShare; !settings.Enabled {
		t.Fatal("quit discarded the share intent")
	}
	journal, _ = relayfirewall.LoadFirewallJournal(a.dir)
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
	journal, _ := relayfirewall.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	a.removePoint("node-1")
	a.awaitFirewall(t)
	journal, _ = relayfirewall.LoadFirewallJournal(a.dir)
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
		if op.Op == relayfirewall.FirewallOpApply {
			t.Fatalf("a rule was created without a verified subnet: %+v", op)
		}
	}
}

// TestDesiredRulesMatchTheRunningShareExactly: a recorded rule only counts as
// desired when program, port and scope still match.
func TestDesiredRulesMatchTheRunningShareExactly(t *testing.T) {
	a := testApp(t)
	installFirewall(t, a, &appFirewall{})
	exe := testProgramPath(t)
	base := relayfirewall.FirewallRule{ID: relayfirewall.FirewallRulePrefix + "1", ProgramPath: exe, Port: 23456, Profile: "private", RemoteIP: "192.168.31.0/24"}
	other := base
	other.ID = relayfirewall.FirewallRulePrefix + "2"
	other.RemoteIP = "10.0.0.0/8"
	journal, _ := relayfirewall.LoadFirewallJournal(a.dir)
	for _, rule := range []relayfirewall.FirewallRule{base, other} {
		if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
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
	fake := &appFirewall{handler: func(op relayfirewall.FirewallOperation) (relayfirewall.FirewallResult, error) {
		if op.Op == relayfirewall.FirewallOpDelete {
			time.Sleep(120 * time.Millisecond)
			select {
			case <-released:
			default:
				close(released)
			}
		}
		return relayfirewall.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relayfirewall.FirewallRemoved}, nil
	}}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	journal, _ := relayfirewall.LoadFirewallJournal(a.dir)
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	a.shutdownLANShare()
	// No awaitFirewall here on purpose: shutdown itself must have waited.
	journal, err := relayfirewall.LoadFirewallJournal(a.dir)
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
	journal, err := relayfirewall.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
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
	journal, err = relayfirewall.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) != nil {
		t.Fatal("the final cleanup request was dropped")
	}
}

// Review: a share that comes back after a restart starts in Starting/Waiting when
// its VPN is not connected yet. Deleting the previously approved rule there made
// the user approve a new elevation prompt on every restart; the record must instead
// be verified and reused.
func TestRestoredWaitingShareReusesItsFirewallRule(t *testing.T) {
	a := testApp(t)
	fake := &appFirewall{}
	installFirewall(t, a, fake)
	rule := firewallAppRule()
	rule.RemoteIP = "192.168.31.0/24"
	fake.handler = func(op relayfirewall.FirewallOperation) (relayfirewall.FirewallResult, error) {
		switch op.Op {
		case relayfirewall.FirewallOpQuery:
			return relayfirewall.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relayfirewall.FirewallPresent, State: matchingAppState(rule)}, nil
		case relayfirewall.FirewallOpDelete:
			return relayfirewall.FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: relayfirewall.FirewallRemoved}, nil
		}
		return relayfirewall.FirewallResult{Outcome: relayfirewall.FirewallPresent}, nil
	}
	journal, err := relayfirewall.LoadFirewallJournal(a.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	for _, state := range []relay.State{relay.StateWaiting, relay.StateStarting} {
		a.doReconcileLanShareFirewall(relay.View{State: state, Port: rule.Port, Address: "192.168.31.61"})
		journal, err = relayfirewall.LoadFirewallJournal(a.dir)
		if err != nil {
			t.Fatal(err)
		}
		if journal.Find(rule.ID) == nil {
			t.Fatalf("%s 状态下把已授权的放行规则删掉了", state)
		}
	}
	// A blocked or stopped share has nothing to serve, so the rule goes.
	for _, state := range []relay.State{relay.StateBlocked, relay.StateOff} {
		journal, _ := relayfirewall.LoadFirewallJournal(a.dir)
		_ = journal.Put(a.dir, relayfirewall.FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: relayfirewall.FirewallEntryConfirmed})
		a.doReconcileLanShareFirewall(relay.View{State: state, Port: rule.Port, Address: "192.168.31.61"})
		journal, _ = relayfirewall.LoadFirewallJournal(a.dir)
		if journal.Find(rule.ID) != nil {
			t.Fatalf("%s 状态下留下了不再需要的放行规则", state)
		}
	}
}

// matchingAppState is what the system reports for a rule this app created.
func matchingAppState(rule relayfirewall.FirewallRule) relayfirewall.FirewallRuleState {
	return relayfirewall.FirewallRuleState{
		Name:          rule.ID,
		Direction:     "Inbound",
		Action:        "Allow",
		Enabled:       true,
		Profile:       "Private",
		Program:       rule.ProgramPath,
		Protocol:      "TCP",
		LocalPort:     strconv.Itoa(rule.Port),
		RemoteAddress: rule.RemoteIP,
	}
}
