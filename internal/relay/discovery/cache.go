package discovery

import (
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
)

// instanceState is the per-(instance, interface) assembly of the record types
// that name the instance. PTR answers "this instance exists", SRV "at this host
// and port", TXT "with this share ID and name". A candidate only exists while
// all three are present and unexpired and the SRV host has a live address,
// which is what makes a partial or hostile answer unusable instead of
// half-believed.
type instanceState struct {
	instance string
	iface    string

	ptrSeen bool
	ptrExp  time.Time

	srvSeen bool
	srvHost string
	srvPort int
	srvExp  time.Time

	txtSeen bool
	txt     txtFields
	txtExp  time.Time

	observed time.Time
}

// freshened reports whether any record of this instance is still alive. A
// partial answer (only a PTR, say) is kept until its TTL runs out so the
// remaining records can complete it; deleting it earlier would make every
// split answer unusable.
func (s *instanceState) freshened(now time.Time) bool {
	return (s.ptrSeen && now.Before(s.ptrExp)) ||
		(s.srvSeen && now.Before(s.srvExp)) ||
		(s.txtSeen && now.Before(s.txtExp))
}

// live reports whether every record needed for a candidate is present.
func (s *instanceState) live(now time.Time) bool {
	return s.ptrSeen && now.Before(s.ptrExp) &&
		s.srvSeen && now.Before(s.srvExp) &&
		s.txtSeen && now.Before(s.txtExp)
}

// cache assembles records into candidates, bounded in both directions: it keeps
// at most MaxCandidates endpoints and at most MaxAddressesPerInstance addresses
// per host. Overflow is dropped instead of evicting a real entry, so a forged
// flood cannot hide the share the user is looking for.
//
// Address records are keyed by (interface, host) because an A record names the
// SRV target host, not the instance; keeping them separate is what lets the
// four record types arrive in any order.
// Bounds on the *incomplete* state, not only on finished candidates. A
// PTR-only instance and an address record for an unknown owner are both memory a
// sender can fill without ever producing a usable share, so they get the same
// kind of ceiling as the candidate list.
const (
	// MaxPartialInstances bounds instances that have not become candidates yet.
	MaxPartialInstances = MaxCandidates
	// MaxHostBuckets bounds the distinct owner names that carry address records.
	MaxHostBuckets = MaxCandidates
)

// partialTTL is how long an instance may stay incomplete. A responder that sends
// PTR and then answers the follow-up query completes within milliseconds; one
// that never answers is dropped instead of being kept for the 75 minute PTR TTL.
// It is a variable so tests can shorten it.
var partialTTL = 60 * time.Second

type cache struct {
	// mu guards every field below. The receive loop writes while the UI asks
	// for snapshots, so the cache is the synchronisation point.
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]*instanceState
	hosts   map[string]map[string]address
	emitted map[string]Candidate
	max     int
}

// address is one A record.
type address struct {
	ip  string
	exp time.Time
}

func newCache(now func() time.Time) *cache {
	if now == nil {
		now = time.Now
	}
	return &cache{
		now:     now,
		entries: make(map[string]*instanceState),
		hosts:   make(map[string]map[string]address),
		emitted: make(map[string]Candidate),
		max:     MaxCandidates,
	}
}

func cacheKey(instance, iface string) string {
	return strings.ToLower(instance) + "|" + iface
}

func hostKey(iface, host string) string {
	return iface + "|" + strings.ToLower(strings.TrimSuffix(host, "."))
}

// apply folds one record into the cache and returns the transitions it caused.
func (c *cache) apply(rec Record) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	exp := now.Add(time.Duration(rec.TTL) * time.Second)

	if rec.Kind == KindA {
		return c.applyAddress(rec, exp, now)
	}

	key := cacheKey(rec.Instance, rec.Interface)
	state := c.entries[key]
	if state == nil {
		if rec.Gone() {
			return nil
		}
		if len(c.entries) >= MaxPartialInstances {
			// Full of half-assembled instances: refuse the new one instead of
			// evicting an instance that may already be serving the user.
			return nil
		}
		state = &instanceState{
			instance: rec.Instance,
			iface:    rec.Interface,
			observed: now,
		}
		c.entries[key] = state
	}
	switch rec.Kind {
	case KindPTR:
		state.ptrSeen = !rec.Gone()
		state.ptrExp = exp
	case KindSRV:
		if rec.Gone() {
			state.srvSeen = false
			break
		}
		if rec.Port < 1 || rec.Port > 65535 || rec.Host == "" {
			return nil
		}
		state.srvSeen = true
		state.srvHost = rec.Host
		state.srvPort = rec.Port
		state.srvExp = exp
	case KindTXT:
		if rec.Gone() {
			state.txtSeen = false
			break
		}
		fields, err := ParseTXT(rec.TXT)
		if err != nil {
			// A TXT record we cannot validate invalidates the instance: better
			// an entry that disappears than one built from a partial answer.
			state.txtSeen = false
			break
		}
		state.txtSeen = true
		state.txt = fields
		state.txtExp = exp
	default:
		return nil
	}
	return c.transitions(key)
}

// applyAddress stores an A record and refreshes every instance on that
// interface whose SRV target is the named host.
func (c *cache) applyAddress(rec Record, exp, now time.Time) []Event {
	if !rec.Gone() && !usableAddress(rec.IPv4) {
		// Version 1 accepts only private addresses: a public or malformed
		// address is not a share on this LAN, and acting on one would let an
		// announcement point the app outside the local network.
		return nil
	}
	key := hostKey(rec.Interface, rec.Host)
	addrs := c.hosts[key]
	if rec.Gone() {
		if addrs == nil {
			return nil
		}
		delete(addrs, rec.IPv4)
	} else {
		if addrs == nil {
			if len(c.hosts) >= MaxHostBuckets {
				return nil
			}
			addrs = make(map[string]address)
			c.hosts[key] = addrs
		}
		if _, ok := addrs[rec.IPv4]; !ok && len(addrs) >= MaxAddressesPerInstance {
			return nil
		}
		addrs[rec.IPv4] = address{ip: rec.IPv4, exp: exp}
	}
	var events []Event
	for k, state := range c.entries {
		if state.iface != rec.Interface || !sameHost(state.srvHost, rec.Host) {
			continue
		}
		events = append(events, c.transitions(k)...)
	}
	return events
}

// transitions recomputes the candidate of one instance and reports what changed.
// The caller holds c.mu.
func (c *cache) transitions(key string) []Event {
	state := c.entries[key]
	if state == nil {
		return nil
	}
	now := c.now()
	cand, ok := c.candidate(state, now)
	// The previous candidate of this instance is keyed independently: a changed
	// address or port is a removal of the old key plus an addition of the new.
	var stale []string
	for k, v := range c.emitted {
		if strings.EqualFold(v.Instance, state.instance) && v.Interface == state.iface && k != cand.Key() {
			stale = append(stale, k)
		}
	}
	if ok {
		if _, already := c.emitted[cand.Key()]; !already && len(c.emitted)-len(stale) >= c.max {
			// The candidate list is full of entries the user may already be
			// looking at. Withdrawing this instance's old endpoint and then
			// failing to add the new one would make the instance vanish, so it is
			// held exactly as it is; the expiry tick revisits every instance and
			// picks up a slot as soon as one frees up.
			return nil
		}
	}
	var events []Event
	for _, k := range stale {
		events = append(events, Event{Kind: EventRemoved, Candidate: c.emitted[k]})
		delete(c.emitted, k)
	}
	if !ok {
		if !state.freshened(now) {
			delete(c.entries, key)
		}
		return events
	}
	prev, existed := c.emitted[cand.Key()]
	if !existed {
		events = append(events, Event{Kind: EventAdded, Candidate: cand})
	} else if !sameCandidate(prev, cand) {
		events = append(events, Event{Kind: EventUpdated, Candidate: cand})
	}
	c.emitted[cand.Key()] = cand
	return events
}

func (c *cache) candidate(s *instanceState, now time.Time) (Candidate, bool) {
	if !s.live(now) {
		return Candidate{}, false
	}
	addr, ok := c.address(s, now)
	if !ok {
		return Candidate{}, false
	}
	cand := Candidate{
		Pairing:         s.txt.Pairing,
		Instance:        s.instance,
		ShareID:         s.txt.ShareID,
		Name:            s.txt.Name,
		ProtocolVersion: s.txt.ProtocolVersion,
		DraftVersion:    s.txt.DraftVersion,
		Address:         addr,
		Port:            s.srvPort,
		Interface:       s.iface,
		ObservedAt:      s.observed,
		ExpiresAt:       earliest(s.ptrExp, s.srvExp, s.txtExp),
	}
	if cand.Name == "" {
		if sid, ok := shareIDFromLabel(firstLabel(s.instance)); ok {
			cand.Name = "Connect Hub 分享 " + truncate(sid, 6)
		}
	}
	return cand, true
}

// address returns the SRV target's live address, if any. When a host publishes
// several, the lexicographically smallest wins so the list does not flicker.
func (c *cache) address(s *instanceState, now time.Time) (string, bool) {
	addrs := c.hosts[hostKey(s.iface, s.srvHost)]
	var best string
	for _, a := range addrs {
		if !now.Before(a.exp) {
			continue
		}
		if best == "" || a.ip < best {
			best = a.ip
		}
	}
	return best, best != ""
}

// usableAddress reports whether an address received from the network may be
// shown and dialled as a LAN share.
func usableAddress(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return false
	}
	return model.RFC1918(parsed)
}

func sameHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func earliest(times ...time.Time) time.Time {
	var out time.Time
	for _, t := range times {
		if out.IsZero() || t.Before(out) {
			out = t
		}
	}
	return out
}

func firstLabel(name string) string {
	if i := strings.Index(name, "."); i >= 0 {
		return name[:i]
	}
	return name
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func sameCandidate(a, b Candidate) bool {
	return a.ShareID == b.ShareID && a.Name == b.Name && a.Address == b.Address &&
		a.Port == b.Port && a.Interface == b.Interface &&
		a.ProtocolVersion == b.ProtocolVersion && a.DraftVersion == b.DraftVersion && a.Pairing == b.Pairing
}

// expire removes records whose TTL ran out and reports the candidates that
// disappeared. It is how a share vanishes when its goodbye was lost.
func (c *cache) expire() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var keys []string
	for k := range c.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var events []Event
	for _, k := range keys {
		state := c.entries[k]
		if state != nil && !state.live(now) && now.Sub(state.observed) > partialTTL {
			// An instance that never completed is garbage, not a candidate.
			for _, prev := range c.emitted {
				if strings.EqualFold(prev.Instance, state.instance) && prev.Interface == state.iface {
					events = append(events, Event{Kind: EventRemoved, Candidate: prev})
					delete(c.emitted, prev.Key())
				}
			}
			delete(c.entries, k)
			continue
		}
		events = append(events, c.transitions(k)...)
	}
	// Address records and empty host buckets have their own lifetime.
	for hk, addrs := range c.hosts {
		for ip, a := range addrs {
			if !now.Before(a.exp) {
				delete(addrs, ip)
			}
		}
		if len(addrs) == 0 {
			delete(c.hosts, hk)
		}
	}
	return events
}

// snapshot returns an immutable, deterministically ordered view. Ordering by
// display name keeps a row in place while its records refresh.
func (c *cache) snapshot() []Candidate {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Candidate, 0, len(c.emitted))
	for _, v := range c.emitted {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		li, lj := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if li != lj {
			return li < lj
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// reset drops every entry; a new browsing generation starts from nothing.
func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*instanceState)
	c.hosts = make(map[string]map[string]address)
	c.emitted = make(map[string]Candidate)
}
