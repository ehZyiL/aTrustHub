package firewall

import (
	"path/filepath"
	"testing"
)

func TestFirewallRuleValidation(t *testing.T) {
	// The program path must be absolute for the platform under test: a POSIX path
	// is not absolute on Windows, so hardcoding one made this case fail there.
	rule := FirewallRule{
		ID: "ConnectHub-LANShare-1234-1", ProgramPath: filepath.Join(t.TempDir(), "connect-hub"),
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
