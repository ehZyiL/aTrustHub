package capture

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Rules alone cannot prove a DNS lease is healthy: map targets and timeout
// changes must also be checked. nft's JSON durations are rounded seconds.
func (a *aliasRoute) verifyElements(ctx context.Context, run commandFunc) error {
	before, err := bootNow()
	if err != nil {
		return err
	}
	b, err := run(ctx, "nft", "", "-j", "list", "map", "ip", a.table(), "real")
	if err != nil {
		return err
	}
	after, err := bootNow()
	if err != nil {
		return err
	}
	return a.validateElements(b, before, after)
}

func (a *aliasRoute) validateElements(b []byte, before, after int64) error {
	invalid := errors.New("capture: alias destinations or lifetimes changed")
	var data struct {
		NFT []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(b, &data) != nil {
		return invalid
	}
	seen := map[string]bool{}
	found := false
	for _, item := range data.NFT {
		raw, ok := item["map"]
		if !ok {
			continue
		}
		var m struct {
			Family, Table, Name string
			Elem                [][]json.RawMessage
		}
		if json.Unmarshal(raw, &m) != nil || m.Family != "ip" || m.Table != a.table() || m.Name != "real" || found {
			return invalid
		}
		found = true
		for _, pair := range m.Elem {
			if len(pair) != 2 {
				return invalid
			}
			var key struct {
				Elem struct {
					Val     string
					Expires *uint64
					Timeout *uint64
				}
			}
			var target string
			if json.Unmarshal(pair[0], &key) != nil || json.Unmarshal(pair[1], &target) != nil || key.Elem.Expires == nil || key.Elem.Timeout == nil {
				return invalid
			}
			address := key.Elem.Val
			expires, ok := a.expires[address]
			if !ok || seen[address] || a.issued[address] != target || *key.Elem.Timeout > 63 || *key.Elem.Expires > 63 {
				return invalid
			}
			seen[address] = true
			remaining := int64(*key.Elem.Expires) * int64(time.Second)
			if remaining > expires-before+int64(2*time.Second) || remaining+int64(2*time.Second) < expires-after {
				return invalid
			}
		}
	}
	if !found {
		return invalid
	}
	for address, expiry := range a.expires {
		if expiry > after+int64(time.Second) && !seen[address] {
			return invalid
		}
	}
	return nil
}
