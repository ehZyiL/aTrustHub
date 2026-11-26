package contract

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ehzyil/connect-hub/internal/components"
)

func TestRequestBoundsBeforeElevation(t *testing.T) {
	now := time.Now()
	r := Request{Request: components.Request{Version: components.Version, InstanceID: "i", RequestID: "r", Operation: Apply, Deadline: now.Add(time.Minute)}, ScanDir: "scan", Selected: []string{"item"}}
	if err := r.Check(now); err != nil {
		t.Fatal(err)
	}
	r.Selected = make([]string, MaxFindings)
	for i := range r.Selected {
		r.Selected[i] = strings.Repeat("a", 1024)
	}
	if r.Check(now) == nil {
		t.Fatal("oversized request accepted")
	}
	r.Selected = nil
	if r.Check(now) == nil {
		t.Fatal("empty selection accepted")
	}
	r.Operation = "unknown"
	if r.Check(now) == nil {
		t.Fatal("unknown operation accepted")
	}
}

func TestDisplayTextKeepsUTF8(t *testing.T) {
	s := Text(strings.Repeat("中", MaxText))
	if len(s) > MaxText || !utf8.ValidString(s) {
		t.Fatal("invalid bounded display text")
	}
}
