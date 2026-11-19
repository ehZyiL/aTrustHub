package capture

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAliasVerificationDetectsMissingRetargetedAndExtendedEntries(t *testing.T) {
	now := int64(100 * time.Second)
	a := aliasRoute{ID: strings.Repeat("d", 32), issued: map[string]string{"198.19.64.2": "10.0.0.1"}, expires: map[string]int64{"198.19.64.2": now + int64(30*time.Second)}}
	packet := func(elem string) []byte {
		return []byte(fmt.Sprintf(`{"nftables":[{"map":{"family":"ip","table":%q,"name":"real","elem":%s}}]}`, a.table(), elem))
	}
	valid := `[[{"elem":{"val":"198.19.64.2","timeout":30,"expires":29}},"10.0.0.1"]]`
	if err := a.validateElements(packet(valid), now, now); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`[]`, strings.ReplaceAll(valid, "10.0.0.1", "10.0.0.2"), strings.ReplaceAll(valid, `"expires":29`, `"expires":59`),
		strings.ReplaceAll(valid, `"expires":29`, `"expires":1`), strings.ReplaceAll(valid, "198.19.64.2", "198.19.64.3"),
		`[["198.19.64.2","10.0.0.1"]]`,
	} {
		if err := a.validateElements(packet(bad), now, now); err == nil {
			t.Fatal("tampered mapping accepted", bad)
		}
	}
	if err := a.validateElements(packet(`[]`), now+int64(31*time.Second), now+int64(31*time.Second)); err != nil {
		t.Fatal("natural expiry misidentified as tampering", err)
	}
	if err := a.validateElements(packet(valid), now+int64(60*time.Second), now+int64(60*time.Second)); err == nil {
		t.Fatal("stale kernel timeout survived suspend without detection")
	}
}
