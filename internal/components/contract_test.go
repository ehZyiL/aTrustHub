package components

import (
	"strings"
	"testing"
	"time"
)

func TestHandshakeRejectsMismatchAndMissingCapabilities(t *testing.T) {
	h := Hello{Version: Version, InstanceID: "instance-1", Capabilities: []string{"scan", "cancel"}}
	if err := h.Check("scan"); err != nil {
		t.Fatal(err)
	}
	if err := h.Check("restore"); err == nil {
		t.Fatal("accepted unavailable capability")
	}
	h.Version++
	if err := h.Check(); err == nil {
		t.Fatal("accepted incompatible major")
	}
	h.Version = Version
	h.Capabilities = []string{"scan", "scan"}
	if err := h.Check(); err == nil {
		t.Fatal("accepted duplicate capability")
	}
}

func TestDecodeRefusesUnboundedAndAmbiguousMessages(t *testing.T) {
	for _, input := range []string{
		strings.Repeat(" ", MaxMessageBytes+1),
		`{"version":1,"unexpected":true}`,
		`{"version":1} {"version":2}`,
	} {
		var h Hello
		if err := Decode(strings.NewReader(input), &h); err == nil {
			t.Fatal("accepted invalid message")
		}
	}
}

func TestCursorRefusesStaleInstanceRequestAndPostFinalEvents(t *testing.T) {
	c := Cursor{InstanceID: "instance-2", RequestID: "request-2"}
	e := Event{Version: Version, InstanceID: c.InstanceID, RequestID: c.RequestID, Sequence: 1, State: Running}
	old := e
	old.InstanceID = "instance-1"
	if c.Accept(old) {
		t.Fatal("accepted previous process")
	}
	old = e
	old.RequestID = "request-1"
	if c.Accept(old) {
		t.Fatal("accepted previous task")
	}
	if !c.Accept(e) || c.Accept(e) {
		t.Fatal("failed sequence ordering")
	}
	e.Sequence++
	e.Final = true
	e.State = Disabled
	if !c.Accept(e) {
		t.Fatal("refused completion")
	}
	e.Sequence++
	if c.Accept(e) {
		t.Fatal("accepted data after completion")
	}
	e.Detail = strings.Repeat("x", MaxDetailBytes+1)
	if e.Check() == nil {
		t.Fatal("accepted unbounded detail")
	}
}

func TestRequestRequiresIdentityAndDeadline(t *testing.T) {
	now := time.Now()
	r := Request{Version: Version, InstanceID: "instance", RequestID: "request", Operation: "scan", Deadline: now.Add(time.Second)}
	if err := r.Check(now); err != nil {
		t.Fatal(err)
	}
	if r.Check(now.Add(time.Second)) == nil {
		t.Fatal("accepted expired request")
	}
	r.RequestID = ""
	if r.Check(now) == nil {
		t.Fatal("accepted unidentified request")
	}
}
