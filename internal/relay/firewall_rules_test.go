package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeFirewall is a controllable privileged executor. It records every operation
// and lets a test decide the outcome, including blocking until a cancellation
// arrives.
type fakeFirewall struct {
	mu      sync.Mutex
	ops     []FirewallOperation
	handler func(FirewallOperation) (FirewallResult, error)
}

func (f *fakeFirewall) Run(ctx context.Context, op FirewallOperation) (FirewallResult, error) {
	f.mu.Lock()
	f.ops = append(f.ops, op)
	handler := f.handler
	f.mu.Unlock()
	if handler != nil {
		return handler(op)
	}
	return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallPresent}, nil
}

func (f *fakeFirewall) calls() []FirewallOperation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FirewallOperation(nil), f.ops...)
}

func firewallTestRule(port int) FirewallRule {
	return FirewallRule{
		ID:          NewFirewallRuleID(port, time.Unix(0, 1700000000000000000)),
		Name:        "Connect Hub 局域网分享",
		ProgramPath: `C:\Program Files\Connect Hub\connect-hub.exe`,
		Port:        port,
		Profile:     "private",
		RemoteIP:    "192.168.1.0/24",
	}
}

// matchingState builds the read-back the system should produce for rule.
func matchingState(rule FirewallRule) FirewallRuleState {
	return FirewallRuleState{
		Name:          rule.ID,
		Direction:     "Inbound",
		Action:        "Allow",
		Enabled:       true,
		Profile:       "Private",
		Program:       rule.ProgramPath,
		Protocol:      "TCP",
		LocalPort:     "23456",
		RemoteAddress: rule.RemoteIP,
	}
}

func TestFirewallRuleStateVerifiesEveryAttribute(t *testing.T) {
	rule := firewallTestRule(23456)
	state := matchingState(rule)
	if err := state.Matches(rule); err != nil {
		t.Fatalf("a matching rule was rejected: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*FirewallRuleState)
	}{
		{"name", func(s *FirewallRuleState) { s.Name = "Other" }},
		{"direction", func(s *FirewallRuleState) { s.Direction = "Outbound" }},
		{"action", func(s *FirewallRuleState) { s.Action = "Block" }},
		{"enabled", func(s *FirewallRuleState) { s.Enabled = false }},
		{"profile", func(s *FirewallRuleState) { s.Profile = "Public" }},
		{"program", func(s *FirewallRuleState) { s.Program = `C:\Windows\System32\cmd.exe` }},
		{"protocol", func(s *FirewallRuleState) { s.Protocol = "UDP" }},
		{"port", func(s *FirewallRuleState) { s.LocalPort = "3389" }},
		{"remote", func(s *FirewallRuleState) { s.RemoteAddress = "Any" }},
	}
	for _, c := range cases {
		mutated := state
		c.mutate(&mutated)
		if err := mutated.Matches(rule); err == nil {
			t.Fatalf("%s mismatch was accepted as the requested rule", c.name)
		}
	}
	// Profiles are compared as a set: order and spacing do not matter.
	multi := state
	multi.Profile = "Domain, Private"
	ruleMulti := rule
	ruleMulti.Profile = "private,domain"
	if err := multi.Matches(ruleMulti); err != nil {
		t.Fatalf("equivalent profile sets were rejected: %v", err)
	}
	// An equivalent CIDR spelling is the same scope.
	same := state
	same.RemoteAddress = "192.168.1.0/255.255.255.0"
	if err := same.Matches(rule); err != nil {
		t.Fatalf("an equivalent subnet was rejected: %v", err)
	}
}

func TestFirewallOperationIsAClosedSet(t *testing.T) {
	rule := firewallTestRule(23456)
	good := []FirewallOperation{
		{OperationID: "op-1", Op: FirewallOpApply, Rule: rule},
		{OperationID: "op-2", Op: FirewallOpQuery, RuleID: rule.ID},
		{OperationID: "op-3", Op: FirewallOpDelete, RuleID: rule.ID},
	}
	for _, op := range good {
		if err := op.Validate(); err != nil {
			t.Fatalf("valid operation rejected: %+v %v", op, err)
		}
	}
	// A wildcard in the name would let -DisplayName match other rules.
	for _, id := range []string{FirewallRulePrefix + "*", FirewallRulePrefix + "1?", FirewallRulePrefix + "[1]"} {
		op := FirewallOperation{OperationID: "op", Op: FirewallOpDelete, RuleID: id}
		if err := op.Validate(); err == nil {
			t.Fatalf("a wildcard rule id was accepted: %q", id)
		}
	}
	bad := []FirewallOperation{
		{OperationID: "", Op: FirewallOpQuery, RuleID: rule.ID},
		{OperationID: "op", Op: "run", RuleID: rule.ID},
		{OperationID: "op", Op: FirewallOpDelete, RuleID: "SomeoneElsesRule"},
		{OperationID: "op", Op: FirewallOpApply, Rule: FirewallRule{ID: rule.ID, ProgramPath: "relative.exe", Port: 1, Profile: "private"}},
		{OperationID: "op", Op: FirewallOpApply, Rule: FirewallRule{ID: rule.ID, ProgramPath: `C:\x.exe`, Port: 1, Profile: "public"}},
	}
	for _, op := range bad {
		if err := op.Validate(); err == nil {
			t.Fatalf("unsafe operation accepted: %+v", op)
		}
	}
}

func TestFirewallJournalMigratesSchemaOne(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"schema":1,"rules":[{"id":"ConnectHub-LANShare-1-1","programPath":"C:\\a.exe","port":23456,"profile":"private","remoteIp":"192.168.1.0/24"}],"pending":true}`
	if err := os.WriteFile(FirewallJournalPath(dir), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.Entries) != 1 || journal.Entries[0].State != FirewallEntryPending {
		t.Fatalf("schema 1 was not migrated: %+v", journal)
	}
	if !journal.Pending() {
		t.Fatal("an unconfirmed legacy rule must stay pending")
	}
}

func TestRulesApplyConfirmsOnlyAVerifiedRule(t *testing.T) {
	dir := t.TempDir()
	rule := firewallTestRule(23456)
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallCreated, State: matchingState(rule)}, nil
	}
	rules := NewRules(dir, fake, nil)
	result, err := rules.Apply(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != FirewallCreated {
		t.Fatalf("outcome = %s, want created", result.Outcome)
	}
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(journal.Entries) != 1 || journal.Entries[0].State != FirewallEntryConfirmed {
		t.Fatalf("a verified rule was not confirmed: %+v", journal)
	}

	// A rule with the right name but the wrong port is not a success.
	wrong := rule
	wrong.ID = NewFirewallRuleID(23457, time.Unix(0, 1))
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		state := matchingState(wrong)
		state.LocalPort = "3389"
		return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallCreated, State: state}, nil
	}
	result, err = rules.Apply(context.Background(), wrong)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != FirewallFailed {
		t.Fatalf("a mismatched read-back reported %s", result.Outcome)
	}
	journal, err = LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if entry := journal.Find(wrong.ID); entry == nil || entry.State == FirewallEntryConfirmed {
		t.Fatalf("a mismatched rule was confirmed: %+v", journal)
	}
}

func TestRulesCanceledPromptLeavesAnUnconfirmedRecord(t *testing.T) {
	dir := t.TempDir()
	rule := firewallTestRule(23456)
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallCanceled, Detail: "已取消系统授权"}, nil
	}
	rules := NewRules(dir, fake, nil)
	result, err := rules.Apply(context.Background(), rule)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != FirewallCanceled {
		t.Fatalf("outcome = %s, want canceled", result.Outcome)
	}
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The system state is unknown after a cancelled prompt, so the record stays
	// pending for the next verification instead of pretending nothing happened.
	if entry := journal.Find(rule.ID); entry == nil || entry.State != FirewallEntryPending {
		t.Fatalf("a cancelled prompt lost its pending record: %+v", journal)
	}
}

// S3 acceptance: a creation that succeeds after the user closed the share must be
// deleted, never confirmed.
func TestRulesLateSuccessAfterCancelIsRevoked(t *testing.T) {
	dir := t.TempDir()
	rule := firewallTestRule(23456)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		switch op.Op {
		case FirewallOpApply:
			once.Do(func() { close(entered) })
			<-release
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallCreated, State: matchingState(rule)}, nil
		case FirewallOpDelete:
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallRemoved}, nil
		}
		return FirewallResult{Outcome: FirewallPresent}, nil
	}
	rules := NewRules(dir, fake, nil)
	done := make(chan FirewallResult, 1)
	go func() {
		result, _ := rules.Apply(context.Background(), rule)
		done <- result
	}()
	<-entered
	// 关闭共享 happens while the elevation prompt is still open.
	rules.Cancel(rule.ID)
	close(release)
	result := <-done
	if result.Outcome != FirewallCanceled {
		t.Fatalf("outcome = %s, want canceled", result.Outcome)
	}
	calls := fake.calls()
	var deleted bool
	for _, op := range calls {
		if op.Op == FirewallOpDelete && op.RuleID == rule.ID {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("a late creation was not deleted: %+v", calls)
	}
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) != nil {
		t.Fatalf("the revoked rule stayed in the journal: %+v", journal)
	}
}

func TestRulesReconcileKeepsTheRunningRuleAndRemovesTheRest(t *testing.T) {
	dir := t.TempDir()
	keep := firewallTestRule(23456)
	other := firewallTestRule(23457)
	other.RemoteIP = "10.0.0.0/8"
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallRemoved}, nil
	}
	rules := NewRules(dir, fake, nil)
	journal, _ := LoadFirewallJournal(dir)
	for _, rule := range []FirewallRule{keep, other} {
		if err := journal.Put(dir, FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: FirewallEntryConfirmed}); err != nil {
			t.Fatal(err)
		}
	}
	kept, errs := rules.Reconcile(context.Background(), []FirewallRule{keep})
	if len(errs) != 0 {
		t.Fatalf("reconcile failed: %v", errs)
	}
	if kept != 1 {
		t.Fatalf("kept = %d, want 1", kept)
	}
	journal, _ = LoadFirewallJournal(dir)
	if journal.Find(keep.ID) == nil {
		t.Fatal("the rule matching the running share was removed")
	}
	if journal.Find(other.ID) != nil {
		t.Fatal("a rule for a different scope was kept")
	}
}

func TestRulesRecoverVerifiesBeforeReuse(t *testing.T) {
	dir := t.TempDir()
	present := firewallTestRule(23456)
	gone := firewallTestRule(23457)
	changed := firewallTestRule(23458)
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		switch op.RuleID {
		case present.ID:
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallPresent, State: matchingState(present)}, nil
		case gone.ID:
			if op.Op == FirewallOpQuery {
				return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallAbsent}, nil
			}
			return FirewallResult{Outcome: FirewallRemoved}, nil
		case changed.ID:
			if op.Op == FirewallOpQuery {
				state := matchingState(changed)
				state.RemoteAddress = "Any" // an old, wider rule
				return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallPresent, State: state}, nil
			}
			return FirewallResult{Outcome: FirewallRemoved}, nil
		}
		return FirewallResult{Outcome: FirewallAbsent}, nil
	}
	rules := NewRules(dir, fake, nil)
	journal, _ := LoadFirewallJournal(dir)
	for _, rule := range []FirewallRule{present, gone, changed} {
		if err := journal.Put(dir, FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: FirewallEntryConfirmed}); err != nil {
			t.Fatal(err)
		}
	}
	kept, errs := rules.Recover(context.Background(), []FirewallRule{present, gone, changed})
	if len(errs) != 0 {
		t.Fatalf("recover failed: %v", errs)
	}
	if len(kept) != 1 || kept[0].ID != present.ID {
		t.Fatalf("kept = %+v, want only the verified rule", kept)
	}
	journal, _ = LoadFirewallJournal(dir)
	// The gone rule is forgotten, the changed one is removed for its old scope.
	if journal.Find(gone.ID) != nil {
		t.Fatal("a rule that no longer exists stayed in the journal")
	}
	if journal.Find(changed.ID) != nil {
		t.Fatal("an out-of-scope rule was kept")
	}
}

func TestRulesRemoveFailureKeepsTheRecord(t *testing.T) {
	dir := t.TempDir()
	rule := firewallTestRule(23456)
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallDenied, Detail: "系统拒绝授权"}, nil
	}
	rules := NewRules(dir, fake, nil)
	journal, _ := LoadFirewallJournal(dir)
	if err := journal.Put(dir, FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: FirewallEntryConfirmed}); err != nil {
		t.Fatal(err)
	}
	if err := rules.Remove(context.Background(), rule); err == nil {
		t.Fatal("a denied removal reported success")
	}
	journal, _ = LoadFirewallJournal(dir)
	entry := journal.Find(rule.ID)
	if entry == nil || entry.State == FirewallEntryConfirmed {
		t.Fatalf("a failed cleanup lost its record: %+v", journal)
	}
	if !strings.Contains(entry.LastError, "denied") {
		t.Fatalf("the failure reason was not recorded: %+v", entry)
	}
}

func TestSubnetOfMaskUsesTheRealMask(t *testing.T) {
	cases := []struct {
		ip   string
		mask string
		want string
	}{
		{"192.168.31.77", "255.255.255.0", "192.168.31.0/24"},
		{"10.20.30.40", "255.255.0.0", "10.20.0.0/16"},
		{"10.20.30.40", "255.255.254.0", "10.20.30.0/23"},
	}
	for _, c := range cases {
		ip := parseIPv4Mask(t, c.mask)
		got, err := subnetOfMask(c.ip, ip)
		if err != nil {
			t.Fatalf("%s/%s: %v", c.ip, c.mask, err)
		}
		if got != c.want {
			t.Fatalf("%s with mask %s = %q, want %q", c.ip, c.mask, got, c.want)
		}
	}
	if _, err := subnetOfMask("192.168.1.1", parseIPv4Mask(t, "0.0.0.0")); err == nil {
		t.Fatal("a /0 mask must be refused")
	}
}

func parseIPv4Mask(t *testing.T, mask string) net.IPMask {
	t.Helper()
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		t.Fatalf("bad mask %s", mask)
	}
	return net.IPMask(ip)
}

// S2: a program path with spaces and Chinese characters must survive validation,
// the JSON operation file and the read-back comparison unchanged.
func TestFirewallRuleAcceptsSpacesAndChinesePaths(t *testing.T) {
	rule := firewallTestRule(23456)
	rule.ProgramPath = `C:\Program Files\连接中心\connect-hub.exe`
	if err := rule.Validate(); err != nil {
		t.Fatalf("a quoted path with spaces and Chinese text was rejected: %v", err)
	}
	state := matchingState(rule)
	if err := state.Matches(rule); err != nil {
		t.Fatalf("the read-back of the same path failed to match: %v", err)
	}
	op := FirewallOperation{OperationID: "op", Op: FirewallOpApply, Rule: rule}
	data, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	var back FirewallOperation
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Rule.ProgramPath != rule.ProgramPath {
		t.Fatalf("the path changed through the operation file: %q", back.Rule.ProgramPath)
	}
	// Case-insensitive comparison is what Windows does for program paths.
	upper := state
	upper.Program = strings.ToUpper(rule.ProgramPath)
	if err := upper.Matches(rule); err != nil {
		t.Fatalf("a differently cased path was rejected: %v", err)
	}
}

func TestFirewallResultJSONRoundTrip(t *testing.T) {
	// The helper and the desktop speak JSON; a field rename would break the
	// boundary silently, so the wire shape is pinned.
	rule := firewallTestRule(23456)
	result := FirewallResult{OperationID: "op", Op: FirewallOpApply, Outcome: FirewallCreated, Rule: rule, State: matchingState(rule), Detail: "ok"}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"operationId"`, `"outcome"`, `"localPort"`, `"remoteAddress"`, `"program"`} {
		if !strings.Contains(string(data), field) {
			t.Fatalf("result JSON lost %s: %s", field, data)
		}
	}
	var back FirewallResult
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.State.LocalPort != "23456" || back.Outcome != FirewallCreated {
		t.Fatalf("round trip changed the result: %+v", back)
	}
}

// S: Windows PowerShell 5.1 writes a BOM with "-Encoding UTF8". A strict JSON
// decoder then turned a successful rule operation into "结果无法解析". The parser
// must tolerate a BOM, and the helper script must stop writing one.
func TestParseFirewallScriptAnswerToleratesBOM(t *testing.T) {
	rule := firewallTestRule(23456)
	state := matchingState(rule)
	payload := map[string]any{"outcome": "created", "detail": "", "state": map[string]any{
		"name": state.Name, "direction": state.Direction, "action": state.Action,
		"enabled": state.Enabled, "profile": state.Profile, "program": state.Program,
		"protocol": state.Protocol, "localPort": state.LocalPort, "remote": state.RemoteAddress,
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"plain":          body,
		"utf8 bom":       append(append([]byte{}, utf8BOM...), body...),
		"crlf + spaces":  append(append([]byte("\r\n  "), body...), []byte(" \r\n")...),
		"trailing nul":   append(append([]byte{}, body...), 0, 0),
		"bom + newlines": append(append(append([]byte{}, utf8BOM...), body...), '\r', '\n'),
	}
	for name, data := range cases {
		result, err := ParseFirewallScriptAnswer(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result.Outcome != FirewallCreated {
			t.Fatalf("%s: outcome = %s", name, result.Outcome)
		}
		if err := result.State.Matches(rule); err != nil {
			t.Fatalf("%s: state lost through decoding: %v", name, err)
		}
	}
	// UTF-16 output is reported, not silently misparsed.
	if _, err := ParseFirewallScriptAnswer([]byte{0xFF, 0xFE, '{', '}'}); err == nil {
		t.Fatal("UTF-16 output was accepted")
	}
	if _, err := ParseFirewallScriptAnswer(nil); err == nil {
		t.Fatal("an empty answer was accepted")
	}
}

// The helper script must write BOM-less UTF-8: the parser tolerates a BOM, but a
// new helper should not rely on that.
func TestFirewallScriptWritesBomlessUTF8(t *testing.T) {
	if !strings.Contains(psFirewallScript, "UTF8Encoding($false)") {
		t.Fatal("the script does not request BOM-less UTF-8")
	}
	if strings.Contains(psFirewallScript, "Set-Content") {
		t.Fatal("the script still uses Set-Content, which prepends a BOM on 5.1")
	}
	if !strings.Contains(psFirewallScript, "WriteAllText") {
		t.Fatal("the script does not write the result explicitly")
	}
}

// S: pausing a share must revoke a creation that is still waiting for approval.
func TestReconcileCancelsPendingCreationWhenTheShareStops(t *testing.T) {
	dir := t.TempDir()
	rule := firewallTestRule(23456)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		switch op.Op {
		case FirewallOpApply:
			once.Do(func() { close(entered) })
			<-release
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallCreated, State: matchingState(rule)}, nil
		case FirewallOpQuery:
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallAbsent}, nil
		case FirewallOpDelete:
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallRemoved}, nil
		}
		return FirewallResult{Outcome: FirewallPresent}, nil
	}
	rules := NewRules(dir, fake, nil)
	done := make(chan FirewallResult, 1)
	go func() {
		result, _ := rules.Apply(context.Background(), rule)
		done <- result
	}()
	<-entered

	// The share stops running (source lost / VPN offline): nothing is desired.
	if _, errs := rules.Reconcile(context.Background(), nil); len(errs) != 0 {
		t.Fatalf("reconcile failed: %v", errs)
	}
	close(release)
	result := <-done
	if result.Outcome != FirewallCanceled {
		t.Fatalf("a creation approved after the share stopped reported %s", result.Outcome)
	}
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) != nil {
		t.Fatalf("a late creation stayed in the journal: %+v", journal)
	}
}

// S: the operation file is UTF-8, but Windows PowerShell 5.1 decodes Get-Content
// with the system ANSI code page unless told otherwise, which would corrupt a
// Chinese program path. Both directions must be explicit.
func TestFirewallScriptUsesExplicitUTF8BothWays(t *testing.T) {
	if strings.Contains(psFirewallScript, "Get-Content") {
		t.Fatal("the script still reads the operation with the default encoding")
	}
	if !strings.Contains(psFirewallScript, "ReadAllText") || !strings.Contains(psFirewallScript, "UTF8Encoding($false)") {
		t.Fatal("the script does not read the operation as UTF-8")
	}
	// The result side must stay BOM-less as well.
	if !strings.Contains(psFirewallScript, "WriteAllText") {
		t.Fatal("the result is not written explicitly")
	}
}

// The operation file we hand the helper must be UTF-8 with no BOM, so the
// explicit read above produces exactly what we marshalled.
func TestFirewallOperationFileIsUTF8(t *testing.T) {
	rule := firewallTestRule(23456)
	rule.ProgramPath = `C:\Program Files\连接中心\connect-hub.exe`
	data, err := json.Marshal(FirewallOperation{OperationID: "op", Op: FirewallOpApply, Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(data) {
		t.Fatal("the operation JSON is not valid UTF-8")
	}
	if !bytes.HasPrefix(data, []byte("{")) {
		t.Fatalf("the operation JSON starts with %q", data[:3])
	}
	if !bytes.Contains(data, []byte("连接中心")) {
		t.Fatal("the Chinese path was not written literally")
	}
	// A decoder told it is UTF-8 must recover the path byte for byte.
	if bytes.Contains(data, utf8BOM) {
		t.Fatal("the operation file must not start with a BOM")
	}
	var back FirewallOperation
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("decoding as UTF-8 failed: %v", err)
	}
	if back.Rule.ProgramPath != rule.ProgramPath {
		t.Fatalf("path = %q", back.Rule.ProgramPath)
	}
}

// S: deleting a rule that "does not exist yet" must not erase the record of a
// creation that is still waiting behind the elevation prompt. The helper outlives
// this process, so a rule can appear after we decided it was gone.
func TestRemoveKeepsTheRecordWhileACreateIsInFlight(t *testing.T) {
	dir := t.TempDir()
	rule := firewallTestRule(23456)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fake := &fakeFirewall{}
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		switch op.Op {
		case FirewallOpApply:
			once.Do(func() { close(entered) })
			<-release
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallCreated, State: matchingState(rule)}, nil
		case FirewallOpDelete:
			// The rule is not there yet: the create has not returned.
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallAbsent}, nil
		}
		return FirewallResult{Outcome: FirewallPresent}, nil
	}
	rules := NewRules(dir, fake, nil)
	applyDone := make(chan struct{})
	go func() {
		_, _ = rules.Apply(context.Background(), rule)
		close(applyDone)
	}()
	<-entered

	// While the create is in flight, a cleanup runs (quit, source lost).
	if err := rules.Remove(context.Background(), rule); err != nil {
		t.Fatalf("remove: %v", err)
	}
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry := journal.Find(rule.ID)
	if entry == nil {
		t.Fatal("the record was dropped while a create was still in flight")
	}
	if entry.State == FirewallEntryConfirmed {
		t.Fatalf("an unverified rule was confirmed: %+v", entry)
	}

	// The create now succeeds after everything asked it to go away. The record has
	// to survive so the next start can find and delete the rule.
	close(release)
	<-applyDone
	journal, err = LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) == nil {
		t.Fatal("a late creation left no recovery record")
	}
	// And the next start recovers it: query says absent (it was deleted by the
	// cancelled apply), so the record is cleaned up rather than leaking.
	fake.handler = func(op FirewallOperation) (FirewallResult, error) {
		if op.Op == FirewallOpQuery {
			return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallAbsent}, nil
		}
		return FirewallResult{OperationID: op.OperationID, Op: op.Op, Outcome: FirewallRemoved}, nil
	}
	if _, errs := rules.Recover(context.Background(), nil); len(errs) != 0 {
		t.Fatalf("recover: %v", errs)
	}
	journal, err = LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if journal.Find(rule.ID) != nil {
		t.Fatal("the recovery record was not cleared after verification")
	}
}
