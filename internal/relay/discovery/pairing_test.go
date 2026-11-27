package discovery

import "testing"

func TestPairCapabilityIsAdditiveAndNotTrust(t *testing.T) {
	ann := testAnnouncement(1, "test")
	old := BuildTXT(ann)
	if len(old) != 4 {
		t.Fatal("legacy announcement changed")
	}
	ann.Pairing = true
	parts := BuildTXT(ann)
	parsed, err := ParseTXT(parts)
	if err != nil || !parsed.Pairing || parsed.DraftVersion != 1 || parsed.ProtocolVersion != 1 {
		t.Fatal("new capability/version", err)
	}
	if parsed, err = ParseTXT(append(old, "future=ignored")); err != nil || parsed.Unknown != 1 || parsed.Pairing {
		t.Fatal("unknown field compatibility", err)
	}
	if parsed, err = ParseTXT(append(old, "pair=unrecognized")); err != nil || parsed.Pairing {
		t.Fatal("unknown PAKE selected", err)
	}
}
