package capture

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAliasCgroupDisplayChangeKeepsIdentityButDetectsSubstitution(t *testing.T) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	group := strings.TrimPrefix(strings.TrimSpace(string(data)), "0::/")
	if group == "" || strings.Contains(group, "\n") {
		t.Skip("requires a unified cgroup")
	}
	a := &aliasRoute{Groups: []string{group}}
	match := func(right string) map[string]any {
		return map[string]any{"left": map[string]any{"socket": map[string]any{"key": "cgroupv2"}}, "right": right, "op": "=="}
	}
	named, err := a.canonicalCgroupMatches(match(group))
	if err != nil {
		t.Fatal(err)
	}
	id := a.groupIDs[group]
	if id == "" {
		t.Fatal("kernel group identity was not recorded")
	}
	numeric, err := a.canonicalCgroupMatches(match(id))
	if err != nil {
		t.Fatal(err)
	}
	x, _ := json.Marshal(named)
	y, _ := json.Marshal(numeric)
	if string(x) != string(y) {
		t.Fatal("nft display representation changes identity")
	}
	other, err := a.canonicalCgroupMatches(match(id + "1"))
	if err != nil {
		t.Fatal(err)
	}
	z, _ := json.Marshal(other)
	if string(x) == string(z) {
		t.Fatal("another cgroup ID bypasses rule verification")
	}
	for _, path := range []string{"../" + group, "/" + group, "unknown/group"} {
		if _, err := a.canonicalCgroupMatches(match(path)); err == nil {
			t.Fatalf("unexpected group path accepted: %s", path)
		}
	}
}
