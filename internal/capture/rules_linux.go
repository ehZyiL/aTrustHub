package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/resolved"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type commandFunc func(context.Context, string, string, ...string) ([]byte, error)

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p)+b.Len() > 4<<20 {
		return 0, errors.New("capture: command output is too large")
	}
	return b.Buffer.Write(p)
}

// Only these absolute, system-owned tools are ever executed with privilege.
// User input is never interpreted as shell text or a command path.
func systemCommand(ctx context.Context, tool, input string, args ...string) ([]byte, error) {
	if tool != "ip" && tool != "nft" && tool != "busctl" {
		return nil, errors.New("capture: unsupported system tool")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	path := "/usr/bin/" + tool
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		path = "/usr/sbin/" + tool
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/usr/sbin", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr boundedOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		// The commands contain only kernel configuration, never proxy secrets.
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 400 {
			detail = detail[:400]
		}
		return nil, fmt.Errorf("capture: %s failed: %w (%s)", tool, err, detail)
	}
	return stdout.Bytes(), nil
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("operating system random source unavailable")
	}
	return hex.EncodeToString(b[:])
}

// A journal records ownership before the first kernel change. It deliberately
// contains neither application arguments nor VPN/SOCKS credentials.
type ruleLease struct {
	Version        int               `json:"version"`
	ID             string            `json:"id"`
	UID            int               `json:"uid"`
	Group          string            `json:"group"`
	Mark           uint32            `json:"mark"`
	Table          uint32            `json:"table"`
	Pref           int               `json:"pref"`
	Port           int               `json:"port"`
	OutputPriority int               `json:"outputPriority"`
	NFTDigest      string            `json:"nftDigest,omitempty"`
	DNS            *resolved.Lease   `json:"dns,omitempty"`
	Networks       []netpolicy.Range `json:"networks,omitempty"`
}

func (l ruleLease) tableName() string  { return "ech_" + l.ID }
func (l ruleLease) owner() string      { return "easyconnect-hub:v1:" + l.ID }
func (l ruleLease) markString() string { return fmt.Sprintf("0x%x/0x%x", l.Mark, l.Mark) }

func (l ruleLease) validate(uid int) error {
	if (l.Version < 1 || l.Version > ProtocolVersion) || (l.Version == 1 && l.DNS != nil) || (l.Version < 3 && len(l.Networks) > 0) || l.UID != uid || !validScope(uid, l.ID, l.Group) ||
		l.Mark < 1<<24 || l.Mark&(l.Mark-1) != 0 || l.Table < 10000 || l.Table > 0x7fffffff ||
		l.Pref < 1 || l.Pref > 4096 || l.Port < 1024 || l.Port > 65535 ||
		l.OutputPriority < 1 || l.OutputPriority > 1000 ||
		(l.NFTDigest != "" && (len(l.NFTDigest) != 64 || !sessionPattern.MatchString(l.NFTDigest[:32]) || !sessionPattern.MatchString(l.NFTDigest[32:]))) {
		return errors.New("capture: invalid ownership journal")
	}
	if err := netpolicy.Validate(l.Networks); err != nil {
		return err
	}
	if l.DNS != nil {
		return l.DNS.Validate()
	}
	return nil
}

type kernelState struct {
	rules  []map[string]any
	routes []map[string]any
	nft    []map[string]any
}

func decodeJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d.Decode(v)
}

func snapshot(ctx context.Context, run commandFunc) (s kernelState, err error) {
	b, err := run(ctx, "ip", "", "-j", "-N", "-4", "rule", "show")
	if err != nil {
		return s, err
	}
	if err = decodeJSON(b, &s.rules); err != nil {
		return s, err
	}
	b, err = run(ctx, "ip", "", "-j", "-N", "-4", "route", "show", "table", "all")
	if err != nil {
		return s, err
	}
	if err = decodeJSON(b, &s.routes); err != nil {
		return s, err
	}
	b, err = run(ctx, "nft", "", "-j", "list", "ruleset")
	if err != nil {
		return s, err
	}
	var n struct {
		NFT []map[string]any `json:"nftables"`
	}
	if err = decodeJSON(b, &n); err != nil {
		return s, err
	}
	s.nft = n.NFT
	return s, nil
}

func number(v any) (uint32, bool) {
	var s string
	switch x := v.(type) {
	case json.Number:
		s = string(x)
	case string:
		s = x
	default:
		return 0, false
	}
	n, err := strconv.ParseUint(s, 0, 32)
	return uint32(n), err == nil
}

func hasMark(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if k == "meta" || k == "ct" {
				if m, ok := child.(map[string]any); ok && m["key"] == "mark" {
					return true
				}
			}
			if hasMark(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if hasMark(child) {
				return true
			}
		}
	}
	return false
}

func markConstants(v any) (mask uint32, dynamic bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			// A copied conntrack mark or a map can contain values not visible
			// in this ruleset. Refuse allocation rather than assume a free bit.
			if k == "ct" || k == "map" || k == "numgen" || k == "jhash" {
				dynamic = true
			}
			if k == "payload" || k == "rt" || k == "socket" || k == "fib" || k == "symhash" {
				dynamic = true
			}
			if k == "meta" {
				if m, ok := child.(map[string]any); !ok || m["key"] != "mark" {
					dynamic = true
				}
			}
			m, d := markConstants(child)
			mask |= m
			dynamic = dynamic || d
		}
	case []any:
		for _, child := range x {
			m, d := markConstants(child)
			mask |= m
			dynamic = dynamic || d
		}
	default:
		if s, ok := v.(string); ok && strings.HasPrefix(s, "@") {
			dynamic = true
		}
		if n, ok := number(v); ok {
			mask |= n
		}
	}
	return
}

func allocate(s kernelState, uid int, id, group string, port int, known ...ruleLease) (ruleLease, error) {
	l := ruleLease{Version: ProtocolVersion, UID: uid, ID: id, Group: group, Port: port, Pref: 1, OutputPriority: 300}
	routing, err := allocateRouting(s, known...)
	if err != nil {
		return l, err
	}
	l.Mark, l.Table, l.Pref = routing.Mark, routing.Table, routing.Pref
	for _, item := range s.nft {
		if chain, ok := item["chain"].(map[string]any); ok && chain["hook"] == "output" {
			if p, ok := chain["prio"].(json.Number); ok {
				n, _ := strconv.Atoi(string(p))
				if n >= l.OutputPriority {
					l.OutputPriority = n + 1
				}
			}
		}
	}
	return l, l.validate(uid)
}

type routingAllocation struct {
	Mark  uint32
	Table uint32
	Pref  int
}

func (r routingAllocation) valid() bool {
	return r.Mark >= 1<<24 && r.Mark&(r.Mark-1) == 0 && r.Table >= 10000 && r.Table <= 0x7fffffff && r.Pref > 0 && r.Pref <= 4096
}

func allocateRouting(s kernelState, known ...ruleLease) (routingAllocation, error) {
	l := routingAllocation{Pref: 1}
	var used uint32
	tables := map[uint32]bool{253: true, 254: true, 255: true}
	priorities := map[uint32]bool{}
	firstForeign := uint32(4097)
	for _, r := range s.rules {
		if p, ok := number(r["priority"]); ok {
			priorities[p] = true
			table, _ := number(r["table"])
			if p == 0 && r["table"] != "local" && table != 255 {
				return l, errors.New("capture: nonstandard priority-zero policy rule")
			}
			managed := false
			for _, owned := range known {
				if ruleOwned(r, owned) {
					managed = true
					break
				}
			}
			if p > 0 && !managed && p < firstForeign {
				firstForeign = p
			}
		}
		if n, ok := number(r["table"]); ok {
			tables[n] = true
		}
		if n, ok := number(r["fwmark"]); ok {
			if mask, ok := number(r["fwmask"]); ok && mask != ^uint32(0) {
				used |= mask
			} else {
				used |= n
			}
		}
	}
	for l.Pref <= 4096 && priorities[uint32(l.Pref)] {
		l.Pref++
	}
	if uint32(l.Pref) >= firstForeign {
		return l, errors.New("capture: no policy priority available before existing rules")
	}
	for _, r := range s.routes {
		if n, ok := number(r["table"]); ok {
			tables[n] = true
		}
	}
	for _, item := range s.nft {
		if rule, ok := item["rule"].(map[string]any); ok {
			if exprs, ok := rule["expr"].([]any); ok {
				for _, e := range exprs {
					if !hasMark(e) {
						continue
					}
					mask, dynamic := markConstants(e)
					if dynamic {
						return l, errors.New("capture: dynamic nftables marks require a coexistence adapter")
					}
					used |= mask
				}
			}
		}
	}
	for bit := uint32(1 << 30); bit >= 1<<24; bit >>= 1 {
		if bit&used == 0 {
			l.Mark = bit
			break
		}
	}
	if l.Mark == 0 {
		return l, errors.New("capture: no conflict-free packet mark available")
	}
	for range 128 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return l, err
		}
		n := 10000 + binary.BigEndian.Uint32(b[:])%1000000000
		if !tables[n] {
			l.Table = n
			break
		}
	}
	if !l.valid() {
		return l, errors.New("capture: no conflict-free policy routing allocation")
	}
	return l, nil
}

func (l ruleLease) nftScript() string {
	n := l.tableName()
	return fmt.Sprintf(`create table ip %s { comment %q; }
add chain ip %s out { type route hook output priority %d; policy accept; }
add rule ip %s out ip daddr 127.0.0.0/8 return
add rule ip %s out meta skuid %d socket cgroupv2 level %d %q ip protocol tcp meta mark set meta mark | 0x%x
add chain ip %s pre { type filter hook prerouting priority -149; policy accept; }
add rule ip %s pre iifname "lo" meta mark & 0x%x == 0x%x ip protocol tcp tproxy to 127.0.0.1:%d accept
`, n, l.owner(), n, l.OutputPriority, n, n, l.UID, len(strings.Split(l.Group, "/")), l.Group, l.Mark, n, n, l.Mark, l.Mark, l.Port)
}

const routeProtocol = "242"

func installRules(ctx context.Context, run commandFunc, l ruleLease) error {
	if err := l.validate(l.UID); err != nil {
		return err
	}
	script := l.nftScript() + l.guardScript()
	if _, err := run(ctx, "nft", script, "--check", "-f", "-"); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "", "-4", "route", "add", "local", "default", "dev", "lo", "table", strconv.FormatUint(uint64(l.Table), 10), "proto", routeProtocol); err != nil {
		return err
	}
	if _, err := run(ctx, "ip", "", "-4", "rule", "add", "pref", strconv.Itoa(l.Pref), "fwmark", l.markString(), "lookup", strconv.FormatUint(uint64(l.Table), 10), "protocol", routeProtocol); err != nil {
		return err
	}
	_, err := run(ctx, "nft", script, "-f", "-")
	return err
}

func ruleOwned(r map[string]any, l ruleLease) bool {
	p, _ := number(r["priority"])
	m, _ := number(r["fwmark"])
	mask, _ := number(r["fwmask"])
	table, _ := number(r["table"])
	protocol, _ := number(r["protocol"])
	for key := range r {
		switch key {
		case "priority", "fwmark", "fwmask", "table", "protocol", "src":
		default:
			return false
		}
	}
	return p == uint32(l.Pref) && m == l.Mark && mask == l.Mark && table == l.Table && protocol == 242 && r["src"] == "all"
}

func routeOwned(r map[string]any, l ruleLease) bool {
	table, _ := number(r["table"])
	protocol, _ := number(r["protocol"])
	typeNumber, _ := number(r["type"])
	for key := range r {
		switch key {
		case "table", "protocol", "type", "dst", "dev", "scope", "flags":
		default:
			return false
		}
	}
	return table == l.Table && protocol == 242 && (r["type"] == "local" || typeNumber == 2) && (r["dst"] == "default" || r["dst"] == "0.0.0.0/0") && r["dev"] == "lo"
}

func tableOwned(s kernelState, l ruleLease) (exists, ours bool) {
	return namedTableOwned(s, "ip", l.tableName(), l.owner())
}

func namedTableOwned(s kernelState, family, name, owner string) (exists, ours bool) {
	for _, item := range s.nft {
		if t, ok := item["table"].(map[string]any); ok && t["family"] == family && t["name"] == name {
			return true, t["comment"] == owner
		}
	}
	return false, false
}

func verifyRules(ctx context.Context, run commandFunc, l ruleLease) error {
	s, err := snapshot(ctx, run)
	if err != nil {
		return err
	}
	if _, ours := tableOwned(s, l); !ours {
		return errors.New("capture: owned nftables table is missing or replaced")
	}
	if len(l.Networks) > 0 {
		if _, ours := namedTableOwned(s, "inet", l.guardName(), l.guardOwner()); !ours {
			return errors.New("capture: internal UDP/IPv6 guard is missing or replaced")
		}
	}
	digest, err := tableDigest(s, l)
	if err != nil {
		return err
	}
	if l.NFTDigest != "" && digest != l.NFTDigest {
		return errors.New("capture: nftables capture rules were modified")
	}
	var rules, routes int
	for _, r := range s.rules {
		if ruleOwned(r, l) {
			rules++
		}
	}
	for _, r := range s.routes {
		if routeOwned(r, l) {
			routes++
		}
	}
	if rules != 1 || routes != 1 {
		return errors.New("capture: route verification failed")
	}
	return nil
}

func tableDigest(s kernelState, l ruleLease) (string, error) {
	var entries []map[string]any
	chains, rules, sets := 0, 0, 0
	for _, item := range s.nft {
		for kind, value := range item {
			v, ok := value.(map[string]any)
			if !ok {
				continue
			}
			name := v["table"]
			if kind == "table" {
				name = v["name"]
			}
			mainTable := v["family"] == "ip" && name == l.tableName()
			guardTable := len(l.Networks) > 0 && v["family"] == "inet" && name == l.guardName()
			if !mainTable && !guardTable {
				continue
			}
			copy := make(map[string]any, len(v))
			for key, value := range v {
				if key != "handle" {
					copy[key] = value
				}
			}
			entries = append(entries, map[string]any{kind: copy})
			if kind == "chain" {
				chains++
			}
			if kind == "rule" {
				rules++
			}
			if kind == "set" {
				sets++
			}
		}
	}
	wantChains, wantRules, wantSets := 2, 3, 0
	if len(l.Networks) > 0 {
		wantChains++
		wantSets = l.guardRuleCount()
		wantRules += wantSets
	}
	if chains != wantChains || rules != wantRules || sets != wantSets {
		return "", errors.New("capture: nftables capture rules are incomplete")
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}

// Cleanup removes only exact owned objects. A replaced table is not flushed.
// The caller retains the journal when cleanup fails, so restart can retry.
func removeRules(ctx context.Context, run commandFunc, l ruleLease) error {
	return removeRulesUpdatingAliases(ctx, run, l, nil, nil)
}

// Revoke both the transparent ingress and alias selection in one nft commit.
// Otherwise a packet can be DNATed to a real IP while the old scope mark still
// sends it to the VPN dialer without its original domain identity.
func removeRulesUpdatingAliases(ctx context.Context, run commandFunc, l ruleLease, alias *aliasRoute, groups []string) error {
	if alias != nil {
		alias.mu.Lock()
		defer alias.mu.Unlock()
		if err := alias.verifyLocked(ctx, run); err != nil {
			return err
		}
	}
	s, err := snapshot(ctx, run)
	if err != nil {
		return err
	}
	var removals strings.Builder
	tables := []struct{ family, name, owner string }{{"ip", l.tableName(), l.owner()}}
	if len(l.Networks) > 0 {
		tables = append(tables, struct{ family, name, owner string }{"inet", l.guardName(), l.guardOwner()})
	}
	for _, table := range tables {
		if exists, ours := namedTableOwned(s, table.family, table.name, table.owner); exists {
			if !ours {
				return errors.New("capture: nftables table ownership changed; refusing deletion")
			}
			fmt.Fprintf(&removals, "delete table %s %s\n", table.family, table.name)
		}
	}
	if alias != nil {
		previous := alias.Groups
		alias.Groups = append([]string(nil), groups...)
		valid := alias.validate()
		script := alias.selectionRules()
		alias.Groups = previous
		if valid != nil {
			return valid
		}
		fmt.Fprintf(&removals, "flush chain ip %s out\nflush chain ip %s guard\n%s", alias.table(), alias.table(), script)
	}
	if removals.Len() > 0 {
		if _, err := run(ctx, "nft", removals.String(), "-f", "-"); err != nil {
			return err
		}
	}
	if alias != nil {
		alias.Groups = append([]string(nil), groups...)
		alias.digest, err = alias.configurationDigest(ctx, run)
		if err != nil {
			return err
		}
	}
	for _, r := range s.rules {
		if ruleOwned(r, l) {
			if _, err := run(ctx, "ip", "", "-4", "rule", "del", "pref", strconv.Itoa(l.Pref), "fwmark", l.markString(), "lookup", strconv.FormatUint(uint64(l.Table), 10), "protocol", routeProtocol); err != nil {
				return err
			}
		}
	}
	for _, r := range s.routes {
		if routeOwned(r, l) {
			if _, err := run(ctx, "ip", "", "-4", "route", "del", "local", "default", "dev", "lo", "table", strconv.FormatUint(uint64(l.Table), 10), "proto", routeProtocol); err != nil {
				return err
			}
		}
	}
	return nil
}
