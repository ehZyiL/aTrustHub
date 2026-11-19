package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAliasJournalRoundtripBoundsAndOwnership(t *testing.T) {
	dir := t.TempDir()
	now, err := bootNow()
	if err != nil {
		t.Fatal(err)
	}
	j := aliasJournal{Version: 1, UID: 1000, ID: strings.Repeat("c", 32), Prefix: "198.19.64.0/20", Entries: map[string]aliasRecord{"198.19.64.2": {Original: "10.90.0.9", Expires: now + int64(30*time.Second)}}}
	if err = saveAliasJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, j.ID+".json")
	got, err := readAliasJournal(path, 1000)
	if err != nil || got.Entries["198.19.64.2"] != j.Entries["198.19.64.2"] {
		t.Fatal(got, err)
	}
	if got.retirement() != now+int64(35*time.Second) {
		t.Fatal("retirement window lost")
	}
	if _, err := readAliasJournal(path, 1001); err == nil {
		t.Fatal("another UID journal accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAliasJournal(path, 1000); err == nil {
		t.Fatal("public journal accepted")
	}
	j.Entries["198.19.64.2"] = aliasRecord{Original: "127.0.0.1", Expires: now}
	if err = saveAliasJournal(dir, j); err == nil {
		t.Fatal("unsafe journal target persisted")
	}
}
