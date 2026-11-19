package netpolicy

import (
	"reflect"
	"testing"
)

func TestRangesRejectAmbiguousOrUnsafeAddresses(t *testing.T) {
	for _, r := range []Range{
		{"10.0.0.1;flush ruleset", "10.0.0.2"}, {"10.0.0.2", "10.0.0.1"},
		{"10.0.0.1", "fd00::1"}, {"::ffff:10.0.0.1", "::ffff:10.0.0.1"},
		{"fd00::1%eth0", "fd00::1%eth0"}, {"0.0.0.0", "255.255.255.255"},
		{"10.0.0.1", "192.168.0.1"}, {"::1", "fd00::1"},
	} {
		if err := Validate([]Range{r}); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}

func TestCompactKeepsGapsAndAddressFamilies(t *testing.T) {
	got, err := Compact([]Range{{"10.0.0.2", "10.0.0.4"}, {"fd00::2", "fd00::4"}, {"10.0.0.1", "10.0.0.2"}, {"10.0.0.6", "10.0.0.6"}, {"fd00::1", "fd00::1"}})
	want := []Range{{"10.0.0.1", "10.0.0.4"}, {"10.0.0.6", "10.0.0.6"}, {"fd00::1", "fd00::4"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
