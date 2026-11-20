package capture

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"time"
)

func sharedPrefix(shared map[string]*sharedAliases, prefix string) bool {
	for _, alias := range shared {
		if alias.route.Prefix == prefix {
			return true
		}
	}
	return false
}

// Exclude only verified tables of the capabilities being transferred. Other
// users' journals, kernel routes and nftables literals remain reservations.
func (r *systemRuntime) sharedAliasState(ctx context.Context, state kernelState, shared map[string]*sharedAliases) (kernelState, error) {
	now, err := bootNow()
	if err != nil {
		return state, err
	}
	tables := map[string]bool{}
	for _, alias := range shared {
		if err := alias.journal.validate(alias.route.UID); err != nil {
			return state, err
		}
		for _, entry := range alias.journal.Entries {
			if entry.Expires > now+int64(63*time.Second) || netip.MustParsePrefix("198.18.0.0/15").Contains(netip.MustParseAddr(entry.Original)) {
				return state, errors.New("capture: invalid shared DNS lifetime or destination")
			}
		}
		exists, _ := namedTableOwned(state, "ip", alias.route.table(), alias.route.owner())
		if alias.dormant {
			if exists {
				return state, errors.New("capture: dormant DNS pool has unexpected kernel rules")
			}
			continue
		}
		alias.route.mu.Lock()
		err := alias.route.verifyLocked(ctx, r.run)
		alias.route.mu.Unlock()
		if err != nil {
			return state, err
		}
		tables[alias.route.table()] = true
	}
	var nft []map[string]any
	for _, entry := range state.nft {
		owned := false
		for kind, raw := range entry {
			if v, ok := raw.(map[string]any); ok && v["family"] == "ip" {
				name, _ := v["table"].(string)
				if kind == "table" {
					name, _ = v["name"].(string)
				}
				owned = owned || tables[name]
			}
		}
		if !owned {
			nft = append(nft, entry)
		}
	}
	state.nft = nft
	return state, nil
}

func (r *systemRuntime) reserveSharedAliases(shared map[string]*sharedAliases) error {
	next := r.journal
	next.Pools = maps.Clone(next.Pools)
	if next.Pools == nil {
		next.Pools = map[string]int64{}
	}
	for _, alias := range shared {
		if expiry := alias.journal.retirement(); expiry > 0 {
			next.Pools[alias.route.Prefix] = max(next.Pools[alias.route.Prefix], expiry)
		}
	}
	if maps.Equal(next.Pools, r.journal.Pools) {
		return nil
	}
	if err := next.save(r.path); err != nil {
		return err
	}
	r.journal.Pools = next.Pools
	return nil
}

func (r *systemRuntime) suspendSharedAliases(ctx context.Context, shared map[string]*sharedAliases) (func() error, error) {
	var suspended []*sharedAliases
	undo := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		now, err := bootNow()
		if err != nil {
			return err
		}
		var errs []error
		for _, alias := range suspended {
			route, err := restoreAliasJournal(ctx, r.run, alias.journal, now)
			if err == nil {
				alias.route, alias.dormant = route, false
			}
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	for _, alias := range shared {
		if alias.dormant {
			continue
		}
		if err := alias.route.remove(ctx, r.run); err != nil {
			return undo, errors.Join(err, undo())
		}
		alias.dormant = true
		suspended = append(suspended, alias)
	}
	return undo, nil
}

func (r *systemRuntime) usesAlias(alias *sharedAliases) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pool := range r.pools {
		if pool.Alias == alias {
			return true
		}
	}
	return false
}

// Stopping system capture restores only the bounded original destinations.
// It never restores selected application groups or grants a new VPN session.
func (r *systemRuntime) restoreSharedAliases(ctx context.Context, aliases map[string]*sharedAliases) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now, err := bootNow()
	if err != nil {
		return err
	}
	// Include uncommitted leases: a failed apply may have suspended a table
	// and then failed to roll it back before its pool reached r.pools. The
	// service still owns those journals and holds the exclusive mode lock.
	for _, alias := range aliases {
		if !alias.dormant || alias.journal.retirement() <= now {
			continue
		}
		route, err := restoreAliasJournal(ctx, r.run, alias.journal, now)
		if err != nil {
			return err
		}
		alias.route, alias.dormant = route, false
	}
	return nil
}

// Revoke grants before cleanup, including when cleanup subsequently fails.
func (r *systemRuntime) revokeAliasOwner(owner string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	used := false
	for _, pool := range r.pools {
		if pool.Alias != nil && pool.Alias.owner == owner {
			pool.Retired, used = true, true
		}
	}
	return used
}
