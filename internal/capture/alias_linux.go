package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

// aliasRoute is the Linux destination-restoration primitive. The service must
// journal its lease and install it before enabling synthetic DNS. Individual
// scopes share this lease and revoke selection before releasing their ingress.
type aliasRoute struct {
	ID       string
	UID      int
	Prefix   string
	Groups   []string
	mu       sync.Mutex
	issued   map[string]string
	expires  map[string]int64
	digest   string
	groupIDs map[string]string
}

func (a *aliasRoute) table() string { return "echa_" + a.ID }
func (a *aliasRoute) owner() string { return "easyconnect-hub-alias:v1:" + a.ID }

func (a *aliasRoute) validate() error {
	p, err := netip.ParsePrefix(a.Prefix)
	if !sessionPattern.MatchString(a.ID) || a.UID < 1 || err != nil || p != p.Masked() || p.Bits() < 20 || p.Bits() > 24 || !netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(p.Addr()) || len(a.Groups) > maxSessions {
		return errors.New("capture: invalid alias lease")
	}
	for _, group := range a.Groups {
		name := group[strings.LastIndex(group, "/")+1:]
		id := strings.TrimSuffix(strings.TrimPrefix(name, "easyconnect-hub-"), ".scope")
		if !validScope(a.UID, id, group) {
			return errors.New("capture: invalid alias launch group")
		}
	}
	return nil
}

// configurationDigest excludes only timeout map elements. Selection and
// restoration rules are immutable between acknowledged group changes.
func (a *aliasRoute) configurationDigest(ctx context.Context, run commandFunc) (string, error) {
	state, err := snapshot(ctx, run)
	if err != nil {
		return "", err
	}
	if _, ours := namedTableOwned(state, "ip", a.table(), a.owner()); !ours {
		return "", errors.New("capture: alias table missing or replaced")
	}
	var entries []map[string]any
	chains, rules, maps := 0, 0, 0
	for _, entry := range state.nft {
		for kind, raw := range entry {
			v, ok := raw.(map[string]any)
			if !ok || v["family"] != "ip" {
				continue
			}
			name := v["table"]
			if kind == "table" {
				name = v["name"]
			}
			if name != a.table() {
				continue
			}
			copy := map[string]any{}
			for key, value := range v {
				if key != "handle" && !(kind == "map" && key == "elem") {
					copy[key] = value
				}
			}
			if kind == "rule" {
				canonical, err := a.canonicalCgroupMatches(copy)
				if err != nil {
					return "", err
				}
				copy = canonical.(map[string]any)
			}
			entries = append(entries, map[string]any{kind: copy})
			switch kind {
			case "chain":
				chains++
			case "rule":
				rules++
			case "map":
				maps++
			}
		}
	}
	if chains != 3 || maps != 1 || rules != 5+2*len(a.Groups) {
		return "", errors.New("capture: alias routing rules incomplete")
	}
	for group := range a.groupIDs {
		if !slices.Contains(a.Groups, group) {
			delete(a.groupIDs, group)
		}
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}

func (a *aliasRoute) selectors(chain string) string {
	var b strings.Builder
	for _, group := range a.Groups {
		protocol := ""
		if chain == "guard" {
			protocol = "ip protocol tcp "
		}
		// Skip DNAT for every selected protocol. The filter chain permits
		// TCP to reach the worker and rejects unsupported UDP before it can
		// lose its synthetic identity and bypass the per-scope IP guard.
		fmt.Fprintf(&b, "add rule ip %s %s meta skuid %d socket cgroupv2 level %d %q %sreturn\n", a.table(), chain, a.UID, len(strings.Split(group, "/")), group, protocol)
	}
	return b.String()
}

func (a *aliasRoute) selectionRules() string {
	table := a.table()
	script := fmt.Sprintf("add rule ip %s out ip daddr != %s return\n", table, a.Prefix)
	script += a.selectors("out")
	script += fmt.Sprintf("add rule ip %s out dnat to ip daddr map @real\nadd rule ip %s guard ip daddr != %s return\n", table, table, a.Prefix)
	script += a.selectors("guard")
	return script + fmt.Sprintf("add rule ip %s guard reject with icmp type port-unreachable\n", table)
}

func (a *aliasRoute) install(ctx context.Context, run commandFunc) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(); err != nil {
		return err
	}
	_, err := run(ctx, "nft", a.installScript(), "-f", "-")
	if err == nil {
		a.issued = make(map[string]string)
		a.expires = make(map[string]int64)
		a.digest, err = a.configurationDigest(ctx, run)
	}
	return err
}

func (a *aliasRoute) installScript() string {
	table := a.table()
	script := fmt.Sprintf(`create table ip %s { comment %q; }
add map ip %s real { type ipv4_addr : ipv4_addr; flags timeout; }
add chain ip %s out { type nat hook output priority -100; policy accept; }
add chain ip %s guard { type filter hook output priority -99; policy accept; }
`, table, a.owner(), table, table, table)
	script += a.selectionRules()
	script += fmt.Sprintf(`add chain ip %s post { type nat hook postrouting priority 100; policy accept; }
add rule ip %s post ct status dnat ct original ip daddr %s masquerade
`, table, table, a.Prefix)
	return script
}

// setGroups changes only selection chains in one nft transaction. Existing DNS
// mappings and their timeout are retained, including when the last scope exits.
func (a *aliasRoute) setGroups(ctx context.Context, run commandFunc, groups []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.verifyLocked(ctx, run); err != nil {
		return err
	}
	old := a.Groups
	a.Groups = append([]string(nil), groups...)
	success := false
	defer func() {
		if !success {
			a.Groups = old
		}
	}()
	if err := a.validate(); err != nil {
		return err
	}
	state, err := snapshot(ctx, run)
	if err != nil {
		return err
	}
	if _, ours := namedTableOwned(state, "ip", a.table(), a.owner()); !ours {
		return errors.New("capture: alias table ownership changed")
	}
	script := fmt.Sprintf("flush chain ip %s out\nflush chain ip %s guard\n", a.table(), a.table()) + a.selectionRules()
	if _, err = run(ctx, "nft", script, "-f", "-"); err != nil {
		return err
	}
	a.digest, err = a.configurationDigest(ctx, run)
	if err != nil {
		return err
	}
	success = true
	return nil
}

func (a *aliasRoute) publish(ctx context.Context, run commandFunc, aliases []workeripc.DNSAlias) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(); err != nil {
		return err
	}
	if a.issued == nil || len(aliases) > 32 {
		return errors.New("capture: alias route unavailable or batch oversized")
	}
	p := netip.MustParsePrefix(a.Prefix)
	var b strings.Builder
	batch := map[string]workeripc.DNSAlias{}
	for _, alias := range aliases {
		fake, e1 := netip.ParseAddr(alias.Address)
		real, e2 := netip.ParseAddr(alias.Original)
		if e1 != nil || e2 != nil || fake.String() != alias.Address || real.String() != alias.Original || !p.Contains(fake) || !real.Is4() || !real.IsGlobalUnicast() || real.IsLoopback() || real.IsLinkLocalUnicast() || p.Contains(real) || alias.TTL < 1 || alias.TTL > 60 {
			return errors.New("capture: invalid alias mapping")
		}
		if old, ok := a.issued[alias.Address]; ok && old != alias.Original {
			return errors.New("capture: alias cannot be reassigned in one session")
		}
		if old, ok := batch[alias.Address]; ok && old != alias {
			return errors.New("capture: contradictory alias batch")
		}
		batch[alias.Address] = alias
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	// 'destroy element' is idempotent for an expired entry. Removing and
	// adding in one nft transaction refreshes TTL without a missing-map window.
	for address, alias := range batch {
		expiry := now + int64(time.Duration(alias.TTL)*time.Second)
		if previous := a.expires[address]; previous > expiry {
			expiry = previous
		}
		remaining := time.Duration(expiry - now)
		seconds := uint32((remaining + time.Second - 1) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		fmt.Fprintf(&b, "destroy element ip %s real { %s }\n", a.table(), address)
		fmt.Fprintf(&b, "add element ip %s real { %s timeout %ds : %s }\n", a.table(), address, seconds, alias.Original)
	}
	if b.Len() == 0 {
		return a.verifyLocked(ctx, run)
	}
	if err := a.verifyLocked(ctx, run); err != nil {
		return err
	}
	if _, err := run(ctx, "nft", b.String(), "-f", "-"); err != nil {
		return err
	}
	for address, alias := range batch {
		a.issued[address] = alias.Original
		if a.expires == nil {
			a.expires = map[string]int64{}
		}
		expiry := now + int64(time.Duration(alias.TTL)*time.Second)
		if expiry > a.expires[address] {
			a.expires[address] = expiry
		}
	}
	return nil
}

func (a *aliasRoute) verifyLocked(ctx context.Context, run commandFunc) error {
	digest, err := a.configurationDigest(ctx, run)
	if err != nil {
		return err
	}
	if a.digest == "" || a.digest != digest {
		return errors.New("capture: alias routing configuration changed")
	}
	return a.verifyElements(ctx, run)
}

func (a *aliasRoute) remove(ctx context.Context, run commandFunc) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.validate(); err != nil {
		return err
	}
	state, err := snapshot(ctx, run)
	if err != nil {
		return err
	}
	exists, ours := namedTableOwned(state, "ip", a.table(), a.owner())
	if !exists {
		return nil
	}
	if !ours {
		return errors.New("capture: alias table ownership changed; refusing removal")
	}
	_, err = run(ctx, "nft", "", "delete", "table", "ip", a.table())
	if err == nil {
		a.issued = nil
	}
	return err
}
