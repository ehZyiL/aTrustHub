package capture

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/qy/easyconnect/internal/workeripc"
)

func TestAliasPublisherRefusesUnsafeTargetsWithoutCommands(t *testing.T) {
	a := aliasRoute{ID: strings.Repeat("a", 32), UID: 1000, Prefix: "198.19.64.0/20", issued: map[string]string{"198.19.64.2": "10.0.0.1"}}
	calls := 0
	run := func(context.Context, string, string, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("must not run")
	}
	for _, r := range []workeripc.DNSAlias{
		{Address: "198.19.64.2", Original: "10.0.0.2", TTL: 30},
		{Address: "10.0.0.5", Original: "10.0.0.1", TTL: 30},
		{Address: "198.19.64.3", Original: "127.0.0.1", TTL: 30},
		{Address: "198.19.64.3", Original: "198.19.64.4", TTL: 30},
		{Address: "198.19.64.3", Original: "10.0.0.1;flush ruleset", TTL: 30},
		{Address: "198.19.64.3", Original: "10.0.0.1", TTL: 61},
	} {
		if err := a.publish(context.Background(), run, []workeripc.DNSAlias{r}); err == nil {
			t.Fatal("invalid mapping accepted", r)
		}
	}
	if calls != 0 {
		t.Fatal("invalid mapping reached privileged command runner")
	}
}

func TestAliasRemovalPreservesReplacementTable(t *testing.T) {
	a := aliasRoute{ID: strings.Repeat("b", 32), UID: 1000, Prefix: "198.19.64.0/20"}
	mutations := 0
	run := func(_ context.Context, tool, input string, args ...string) ([]byte, error) {
		if tool == "ip" && strings.Contains(strings.Join(args, " "), "show") {
			return []byte("[]"), nil
		}
		if tool == "nft" && strings.Join(args, " ") == "-j list ruleset" {
			return []byte(`{"nftables":[{"table":{"family":"ip","name":"` + a.table() + `","comment":"other owner"}}]}`), nil
		}
		mutations++
		return nil, errors.New("unexpected mutation")
	}
	if err := a.remove(context.Background(), run); err == nil || mutations > 0 {
		t.Fatal("replacement table changed")
	}
}
