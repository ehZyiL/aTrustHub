package taskio

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ehzyil/connect-hub/internal/components"
)

func TestTailIncrementalPartialAndOversize(t *testing.T) {
	dir, err := NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.jsonl")
	e := components.Event{Version: components.Version, InstanceID: "i", RequestID: "r", Sequence: 1, State: components.Running}
	b, _ := json.Marshal(e)
	half := len(b) / 2
	if err = os.WriteFile(path, b[:half], 0600); err != nil {
		t.Fatal(err)
	}
	var tail Tail
	count := 0
	consume := func(components.Event) error { count++; return nil }
	if err = tail.Read(path, 1<<20, consume); err != nil || count != 0 {
		t.Fatalf("partial: %v %d", err, count)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(append(b[half:], '\n'))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = tail.Read(path, 1<<20, consume); err != nil || count != 1 {
		t.Fatalf("completed: %v %d", err, count)
	}
	if err = tail.Read(path, 1<<20, consume); err != nil || count != 1 {
		t.Fatalf("reread: %v %d", err, count)
	}
	if err = os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	if tail.Read(path, 1<<20, consume) == nil {
		t.Fatal("report truncation ignored")
	}
	tail = Tail{}
	if err = os.WriteFile(path, make([]byte, components.MaxMessageBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if tail.Read(path, 1<<20, consume) == nil {
		t.Fatal("oversized line accepted")
	}
}
