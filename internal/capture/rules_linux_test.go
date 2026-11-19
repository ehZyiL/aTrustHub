package capture

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func inventory(t *testing.T, rules, routes, nft string) kernelState {
	t.Helper()
	var s kernelState
	for _, p := range []struct {
		raw string
		v   any
	}{{rules, &s.rules}, {routes, &s.routes}, {nft, &s.nft}} {
		if err := decodeJSON([]byte(p.raw), p.v); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestAllocationPreservesForeignMarksAndPriorities(t *testing.T) {
	s := inventory(t, `[{"priority":0,"table":"local"},{"priority":5210,"fwmark":"0x80000","fwmask":"0xff0000","table":"main"},{"priority":5270,"table":"52"},{"priority":9000,"table":"2022"}]`, `[{"table":"2022"}]`,
		`[{"chain":{"hook":"output","prio":310}},{"rule":{"expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1073741824}}]}}]`)
	id := strings.Repeat("a", 32)
	l, err := allocate(s, 1000, id, scopePath(1000, id), 20000)
	if err != nil {
		t.Fatal(err)
	}
	if l.Mark != 0x20000000 || l.Pref != 1 || l.OutputPriority != 311 || l.Table == 2022 || l.Table == 52 {
		t.Fatalf("allocation=%+v", l)
	}
	s.rules = append(s.rules, map[string]any{"priority": json.Number("1"), "protocol": json.Number("242"), "fwmark": "0x20000000", "fwmask": "0x20000000", "src": "all", "table": json.Number(strconv.FormatUint(uint64(l.Table), 10))})
	l, err = allocate(s, 1000, id, scopePath(1000, id), 20000, l)
	if err != nil || l.Pref != 2 || l.Mark != 0x10000000 {
		t.Fatalf("second allocation=%+v, %v", l, err)
	}
}

func TestAllocationRejectsUnverifiableConflict(t *testing.T) {
	for _, tc := range []struct{ name, rules, nft string }{
		{"first priority", `[{"priority":1,"table":"2022"}]`, `[]`},
		{"zero priority", `[{"priority":0,"table":"2022"}]`, `[]`},
		{"unknown marks", `[]`, `[{"rule":{"expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":{"ct":{"key":"mark"}}}}]}}]`},
		{"all bits", `[{"fwmark":"0x80000","fwmask":"0xffffffff"}]`, `[{"rule":{"expr":[{"match":{"left":{"meta":{"key":"mark"}},"right":4294967295}}]}}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := inventory(t, tc.rules, `[]`, tc.nft)
			id := strings.Repeat("a", 32)
			if _, err := allocate(s, 1000, id, scopePath(1000, id), 20000); err == nil {
				t.Fatal("conflict accepted")
			}
		})
	}
}

func TestCleanupRefusesReplacedTable(t *testing.T) {
	l := ruleLease{ID: strings.Repeat("a", 32), UID: 1000, Mark: 0x40000000, Table: 11452, Pref: 1}
	mutations := 0
	run := func(_ context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "ip" && strings.Contains(strings.Join(args, " "), "show") {
			return []byte(`[]`), nil
		}
		if tool == "nft" && strings.Join(args, " ") == "-j list ruleset" {
			return []byte(`{"nftables":[{"table":{"family":"ip","name":"` + l.tableName() + `","comment":"another owner"}}]}`), nil
		}
		mutations++
		return nil, errors.New("unexpected mutation")
	}
	if err := removeRules(context.Background(), run, l); err == nil || mutations != 0 {
		t.Fatalf("err=%v mutations=%d", err, mutations)
	}
}

func TestControlFrameBoundsAndStrictDecoding(t *testing.T) {
	for _, data := range []string{`{"version":1,"extra":"ignored?"}` + "\n", `{"version":1} {"version":1}` + "\n", strings.Repeat(" ", maxFrame) + "\n"} {
		var f frame
		if err := readFrame(bufio.NewReaderSize(strings.NewReader(data), maxFrame), &f); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}

func TestLaunchIdentityCannotSelectArbitraryCgroup(t *testing.T) {
	id := strings.Repeat("a", 32)
	for _, group := range []string{"user.slice", "../user.slice", scopePath(1001, id), scopePath(1000, strings.Repeat("b", 32))} {
		if validScope(1000, id, group) {
			t.Fatalf("accepted %s", group)
		}
	}
	if !validScope(1000, id, scopePath(1000, id)) {
		t.Fatal("valid scope refused")
	}
}
