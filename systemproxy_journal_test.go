package main

import (
	"errors"
	"os"
	"testing"
)

// fakeProxy is an in-memory stand-in for the WinINET settings, so the journal
// logic can be verified without touching a real machine's proxy.
type fakeProxy struct {
	enabled  uint64
	server   string
	override string
	writes   int
}

func (f *fakeProxy) ops() captureProxyOps {
	return captureProxyOps{
		read: func() (captureProxySnapshot, error) {
			return captureProxySnapshot{Enabled: f.enabled, Server: f.server, Override: f.override}, nil
		},
		setEnabled: func(v uint64) error { f.enabled = v; return nil },
		setProxy: func(server, override string) error {
			f.writes++
			f.server, f.override = server, override
			return nil
		},
	}
}

func TestSystemProxyJournalRestoresUserValue(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 1, server: "http://10.0.0.9:3128", override: "*.corp;10.*"}
	ops := f.ops()

	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatal(err)
	}
	if f.server != "socks=127.0.0.1:1080" || f.override != "<local>" || f.enabled != 1 {
		t.Fatalf("installed state = %q %q %d", f.server, f.override, f.enabled)
	}

	if err := restoreSystemProxyJournaled(path, ops); err != nil {
		t.Fatal(err)
	}
	if f.server != "http://10.0.0.9:3128" || f.override != "*.corp;10.*" || f.enabled != 1 {
		t.Fatalf("user value not restored: %q %q %d", f.server, f.override, f.enabled)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("resolved record must be removed")
	}
}

// A machine with no proxy at all must end up with the proxy switched off again,
// not with our address left behind.
func TestSystemProxyJournalRestoresAbsentProxy(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{}
	ops := f.ops()
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatal(err)
	}
	if err := restoreSystemProxyJournaled(path, ops); err != nil {
		t.Fatal(err)
	}
	if f.enabled != 0 {
		t.Fatalf("proxy left enabled with no original value: %d", f.enabled)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("resolved record must be removed")
	}
}

// Another program owns the value now: keep it, and keep the record so the user
// still has their original numbers on screen.
func TestSystemProxyJournalKeepsThirdPartyChange(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 1, server: "http://10.0.0.9:3128"}
	ops := f.ops()
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatal(err)
	}
	f.server = "socks=192.168.1.2:1080"
	if err := restoreSystemProxyJournaled(path, ops); err == nil {
		t.Fatal("a third-party value was overwritten")
	}
	if f.server != "socks=192.168.1.2:1080" {
		t.Fatalf("third-party value changed to %q", f.server)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("record must be kept while it is unresolved")
	}
}

// Crash between writing the record and writing the registry: the current value
// still equals Before, so the record is simply dropped.
func TestSystemProxyJournalCrashBeforeApply(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 0, server: ""}
	record := systemProxyRecord{
		Before:    captureProxySnapshot{Enabled: 0},
		Installed: captureProxySnapshot{Enabled: 1, Server: "socks=127.0.0.1:1080"},
	}
	if err := writeSystemProxyRecord(path, record); err != nil {
		t.Fatal(err)
	}
	if err := restoreSystemProxyJournaled(path, f.ops()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("record must be dropped when nothing was applied")
	}
}

// An unresolved record that is merely *stale* (its Installed value no longer in
// the registry because another program took over) no longer blocks a takeover:
// the scenario and its new contract live in TestTakeoverAfterThirdPartyChange.
// What must still block is a record that cannot be parsed or verified.
func TestCorruptRecordDoesNotBlockAnExplicitTakeover(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeProxy{enabled: 1, server: "socks=192.168.1.2:1080"}
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", f.ops(), nil); err != nil {
		t.Fatalf("a corrupt record blocked the takeover: %v", err)
	}
	if f.server != "socks=127.0.0.1:1080" {
		t.Fatalf("registry = %q", f.server)
	}
	if _, statErr := os.Stat(path + ".broken"); statErr != nil {
		t.Fatal("the corrupt record must be kept aside for inspection")
	}
}

// Applying twice with the machine already pointing at this listener records
// nothing and does not lose the original value.
func TestSystemProxyJournalIdempotentApply(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 1, server: "socks=127.0.0.1:1080", override: "<local>"}
	fallbacks := 0
	fallback := func(string, bool) error { fallbacks++; return nil }
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", f.ops(), fallback); err != nil {
		t.Fatal(err)
	}
	if fallbacks != 1 {
		t.Fatalf("already-owned listener should take the plain path, fallbacks = %d", fallbacks)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no record should be written when nothing is replaced")
	}
}

// Platforms that cannot write an address fall back to the plain behaviour rather
// than creating a record they could never restore.
func TestSystemProxyJournalWithoutSetProxy(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	ops := captureProxyOps{read: func() (captureProxySnapshot, error) { return captureProxySnapshot{}, nil }, setEnabled: func(uint64) error { return nil }}
	calls := 0
	fallback := func(string, bool) error { calls++; return nil }
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, fallback); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("fallback not used: %d", calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no record should be written without a setProxy operation")
	}
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err == nil {
		t.Fatal("without fallback and setProxy the apply must fail loudly")
	}
}

// An unreadable record must stop the app from guessing.
func TestSystemProxyJournalRejectsCorruptRecord(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fakeProxy{enabled: 1, server: "socks=127.0.0.1:1080"}
	err := restoreSystemProxyJournaled(path, f.ops())
	if !errors.Is(err, errProxyJournalCorrupt) {
		t.Fatalf("corrupt record error = %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("corrupt record must be kept for inspection")
	}
}

// After another program replaced our value, the user can still take the setting
// over: the value in place becomes the new baseline instead of blocking forever.
func TestTakeoverAfterThirdPartyChange(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 1, server: "http://10.0.0.9:3128"}
	ops := f.ops()
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatal(err)
	}
	// A VPN client takes the setting over while we are running.
	f.server = "socks=192.168.1.2:1080"
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatalf("takeover was blocked by the stale record: %v", err)
	}
	if f.server != "socks=127.0.0.1:1080" || f.enabled != 1 {
		t.Fatalf("registry = %q enabled=%d", f.server, f.enabled)
	}
	// The third party's value is the new baseline: turning the proxy off must put
	// it back rather than leaving ours behind.
	if err := restoreSystemProxyJournaled(path, ops); err != nil {
		t.Fatal(err)
	}
	if f.server != "socks=192.168.1.2:1080" {
		t.Fatalf("new baseline not restored: %q", f.server)
	}
}

// Switching the proxy off must never disable a value another program owns.
func TestTurningOffLeavesThirdPartyProxyAlone(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 1, server: "http://10.0.0.9:3128"}
	ops := f.ops()
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatal(err)
	}
	f.server, f.enabled = "socks=192.168.1.2:1080", 1
	disable, err := releaseSystemProxyJournal(path, ops)
	if err != nil {
		t.Fatal(err)
	}
	if disable {
		t.Fatal("the caller was told to switch the proxy off, which would disable a third party's value")
	}
	if f.server != "socks=192.168.1.2:1080" || f.enabled != 1 {
		t.Fatalf("third-party value changed: %q enabled=%d", f.server, f.enabled)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatal("the unusable record must be dropped")
	}
}

// A healthy record makes the caller restore and not perform a plain disable.
func TestTurningOffRestoresAndDoesNotBlindlyDisable(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	f := &fakeProxy{enabled: 1, server: "http://10.0.0.9:3128", override: "*.corp"}
	ops := f.ops()
	if err := applySystemProxyJournaled(path, "127.0.0.1:1080", ops, nil); err != nil {
		t.Fatal(err)
	}
	disable, err := releaseSystemProxyJournal(path, ops)
	if err != nil || disable {
		t.Fatalf("disable=%v err=%v", disable, err)
	}
	if f.server != "http://10.0.0.9:3128" || f.override != "*.corp" {
		t.Fatalf("user value = %q / %q", f.server, f.override)
	}
}

// With no record at all the caller must perform the plain disable.
func TestTurningOffWithoutRecordDisables(t *testing.T) {
	path := systemProxyJournalPath(t.TempDir())
	disable, err := releaseSystemProxyJournal(path, (&fakeProxy{}).ops())
	if err != nil || !disable {
		t.Fatalf("disable=%v err=%v", disable, err)
	}
}
