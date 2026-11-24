package relay

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDiagnoseSuccess(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	code := fx.code
	// The fixture identity covers 127.0.0.1, and the client verifies that.
	report := Diagnose(context.Background(), code, DiagnoseOptions{Target: "10.1.2.3:443"})
	if report.Failed() {
		t.Fatalf("diagnose reported a failure:\n%s", strings.Join(FormatReport(report), "\n"))
	}
	lines := strings.Join(FormatReport(report), "\n")
	for _, want := range []string{"TCP 连接已建立", "证书指纹与口令一致", "分享登录成功", "业务连接已建立"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("report lacks %q:\n%s", want, lines)
		}
	}
}

func TestDiagnoseWrongFingerprint(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	code := fx.code
	code.Fingerprint = strings.Repeat("0", 64)
	report := Diagnose(context.Background(), code, DiagnoseOptions{})
	if !report.Failed() {
		t.Fatal("wrong pin must fail the identity step")
	}
	if report.Steps[len(report.Steps)-1].Stage != StageTLS {
		t.Fatalf("diagnose continued past a pin mismatch: %+v", report.Steps)
	}
}

func TestDiagnoseRefusedIsNotBlamedOnFirewall(t *testing.T) {
	// Bind then close a port so the connection is refused rather than hanging.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	code := ShareCode{Version: 1, Host: "127.0.0.1", Port: addr.Port,
		ShareID: "x", Token: "y", Fingerprint: strings.Repeat("a", 64)}
	report := Diagnose(context.Background(), code, DiagnoseOptions{Timeout: 2 * time.Second})
	if !report.Failed() {
		t.Fatal("a closed port must fail")
	}
	lines := strings.Join(FormatReport(report), "\n")
	if strings.Contains(lines, "防火墙未放行") {
		t.Fatalf("a refusal must not be reported as a firewall verdict:\n%s", lines)
	}
	if !strings.Contains(lines, "拒绝") && !strings.Contains(lines, "未唯一确定") {
		t.Fatalf("unexpected wording:\n%s", lines)
	}
}

func TestDiagnoseDeniedTargetIsDefinite(t *testing.T) {
	fx := startShareFixture(t, "share-token-123456")
	report := Diagnose(context.Background(), fx.code, DiagnoseOptions{Target: "8.8.8.8:443"})
	if !report.Failed() {
		t.Fatal("an unauthorized target must fail the business step")
	}
	last := report.Steps[len(report.Steps)-1]
	if last.Stage != StageBusiness || last.Uncertain {
		t.Fatalf("denied target should be a definite business fact: %+v", last)
	}
}

func TestFirewallRuleValidation(t *testing.T) {
	rule := FirewallRule{
		ID: "ConnectHub-LANShare-1234-1", ProgramPath: "/opt/app/connect-hub",
		Port: 23456, Profile: "private", RemoteIP: "192.168.1.0/24",
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	bad := []FirewallRule{
		{ID: "OtherApp", ProgramPath: "x", Port: 1, Profile: "private"},
		{ID: "ConnectHub-LANShare-1", ProgramPath: "", Port: 1, Profile: "private"},
		{ID: "ConnectHub-LANShare-1", ProgramPath: "x", Port: 0, Profile: "private"},
		{ID: "ConnectHub-LANShare-1", ProgramPath: "x", Port: 1, Profile: "public"},
		{ID: "ConnectHub-LANShare-1", ProgramPath: "x", Port: 1, Profile: "private", RemoteIP: "not-a-subnet"},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Fatalf("invalid rule accepted: %+v", r)
		}
	}
}

func TestFirewallJournalRoundTrip(t *testing.T) {
	dir := t.TempDir()
	journal, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatalf("missing journal should not fail: %v", err)
	}
	if len(journal.Entries) != 0 || journal.Pending() {
		t.Fatal("fresh journal has rules")
	}
	rule := FirewallRule{ID: "ConnectHub-LANShare-1-1", ProgramPath: "/x/connect-hub", Port: 1000, Profile: "private", RemoteIP: "192.168.1.0/24"}
	if err := journal.Put(dir, FirewallJournalEntry{Rule: rule, OperationID: rule.ID, State: FirewallEntryPending}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadFirewallJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Entries) != 1 || !reloaded.Pending() {
		t.Fatalf("journal not written before creation: %+v", reloaded)
	}
	if err := reloaded.Remove(dir, rule.ID); err != nil {
		t.Fatal(err)
	}
	final, _ := LoadFirewallJournal(dir)
	if len(final.Entries) != 0 {
		t.Fatalf("rule not removed from the journal: %+v", final)
	}
}

func TestLANSubnetOf(t *testing.T) {
	if got := LANSubnetOf("192.168.31.77"); got != "192.168.31.0/24" {
		t.Fatalf("LANSubnetOf = %q", got)
	}
	if got := LANSubnetOf("not-an-ip"); got != "" {
		t.Fatalf("invalid input produced %q", got)
	}
	if got := LANSubnetOf("fd00::1"); got != "" {
		t.Fatalf("IPv6 should not produce a subnet: %q", got)
	}
}

func TestFirewallInfoIsPlatformSpecific(t *testing.T) {
	info := FirewallInfo()
	if info.Platform == "" || len(info.Lines) == 0 {
		t.Fatalf("guidance is empty: %+v", info)
	}
}
