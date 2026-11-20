// Package dnsmapping owns session identities and the lifetime of DNS aliases.
// OS adapters still inspect kernel routes and confirm installation themselves.
package dnsmapping

import (
	"errors"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/workeripc"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type Identity struct {
	Key, GatewayID, Version string
	Generation              int
}
type Target struct {
	Identity
	Domain, Original string
	Expires          time.Time
}
type entry struct {
	Target
	published bool
}
type pool struct {
	identity          Identity
	prefix            netip.Prefix
	retired           bool
	inFlight, streams int
	entries           map[string]entry
}
type Registry struct {
	mu    sync.Mutex
	pools map[string]*pool
	now   func() time.Time
}

func (r *Registry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
func ValidPrefix(p netip.Prefix) bool {
	return p.IsValid() && p == p.Masked() && p.Addr().Is4() && p.Bits() >= 20 && p.Bits() <= 24 && netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(p.Addr())
}

func overlaps(p netip.Prefix, resource netpolicy.Range) bool {
	lo, e1 := netip.ParseAddr(resource.Min)
	hi, e2 := netip.ParseAddr(resource.Max)
	if e1 != nil || e2 != nil || !lo.Is4() || !hi.Is4() {
		return false
	}
	return p.Contains(lo) || p.Contains(hi) || (lo.Compare(p.Addr()) <= 0 && hi.Compare(p.Addr()) >= 0)
}

// Choose is shared by platform adapters after collecting their occupied routes,
// interface addresses, other mapping pools and retired lease reservations.
func Choose(occupied []netip.Prefix, resources []netpolicy.Range) (netip.Prefix, error) {
	for i := 0; i < 16; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 19, byte(i * 16), 0}), 20)
		if available(p, occupied, resources) {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("没有空闲的 DNS 映射池，请保留显式代理或等待旧映射退役")
}

// ChooseRequired preserves a live worker's existing pool only when it is still
// available. Reservations belonging to old helpers or other sessions still win.
func ChooseRequired(occupied []netip.Prefix, resources []netpolicy.Range, raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !ValidPrefix(prefix) || !available(prefix, occupied, resources) {
		return netip.Prefix{}, errors.New("既有 worker DNS 映射池不可用，请重新登录该网关后切换接管模式")
	}
	return prefix, nil
}

func available(p netip.Prefix, occupied []netip.Prefix, resources []netpolicy.Range) bool {
	for _, used := range occupied {
		if used.Overlaps(p) {
			return false
		}
	}
	for _, resource := range resources {
		if overlaps(p, resource) {
			return false
		}
	}
	return true
}

func (r *Registry) prune() {
	now := r.clock()
	for key, p := range r.pools {
		if !p.retired || p.inFlight != 0 || p.streams != 0 {
			continue
		}
		live := false
		for _, e := range p.entries {
			if now.Before(e.Expires) {
				live = true
				break
			}
		}
		if !live {
			delete(r.pools, key)
		}
	}
}

func (r *Registry) Begin(id Identity, prefix string, resources []netpolicy.Range) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	p, e := netip.ParsePrefix(prefix)
	if e != nil || !ValidPrefix(p) || id.Key == "" || id.GatewayID == "" {
		return nil, errors.New("无效映射池身份")
	}
	for _, resource := range resources {
		if overlaps(p, resource) {
			return nil, errors.New("映射池与在线 VPN 资源重叠")
		}
	}
	if r.pools == nil {
		r.pools = make(map[string]*pool)
	}
	lease := r.pools[id.Key]
	if lease != nil {
		if lease.retired || lease.prefix != p || lease.identity != id {
			return nil, errors.New("会话映射池不能重新绑定")
		}
	} else {
		for _, other := range r.pools {
			if other.prefix.Overlaps(p) {
				return nil, errors.New("映射池仍属于其他会话或正在退役")
			}
		}
		lease = &pool{identity: id, prefix: p, entries: map[string]entry{}}
		r.pools[id.Key] = lease
	}
	lease.inFlight++
	var once sync.Once
	return func() { once.Do(func() { r.mu.Lock(); lease.inFlight--; r.prune(); r.mu.Unlock() }) }, nil
}

// CheckPrefix checks a transport acknowledgement without allocating a pool.
// A worker that has answered DNS cannot change pools until its next login.
func (r *Registry) CheckPrefix(id Identity, raw string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !ValidPrefix(prefix) {
		return errors.New("无效 DNS 映射池")
	}
	if current := r.pools[id.Key]; current != nil && (current.retired || current.prefix != prefix || current.identity != id) {
		return errors.New("会话映射池不能重新绑定")
	}
	return nil
}

// Prefix returns the pool already bound to this live worker identity. It does
// not allocate or restore a retired pool.
func (r *Registry) Prefix(id Identity) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	if p := r.pools[id.Key]; p != nil {
		if p.retired || p.identity != id {
			return "", errors.New("会话映射池身份已变化，请重新登录该网关后切换接管模式")
		}
		return p.prefix.String(), nil
	}
	return "", nil
}

func (r *Registry) Stage(key, domain string, aliases []workeripc.DNSAlias) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pools[key]
	if p == nil || p.retired {
		return errors.New("映射会话已结束")
	}
	if domain == "" {
		return errors.New("映射缺少原始域名")
	}
	if len(aliases) > 32 {
		return errors.New("映射容量不足")
	}
	updates := map[string]entry{}
	now := r.clock()
	for _, a := range aliases {
		ip, e1 := netip.ParseAddr(a.Address)
		real, e2 := netip.ParseAddr(a.Original)
		if e1 != nil || e2 != nil || !p.prefix.Contains(ip) || !real.Is4() || !real.IsGlobalUnicast() || real.IsLoopback() || real.IsLinkLocalUnicast() || netip.MustParsePrefix("198.18.0.0/15").Contains(real) || a.TTL == 0 || a.TTL > 60 {
			return errors.New("映射超出会话范围")
		}
		next := entry{Target: Target{Identity: p.identity, Domain: domain, Original: a.Original, Expires: now.Add(time.Duration(a.TTL) * time.Second)}}
		for _, old := range []entry{p.entries[a.Address], updates[a.Address]} {
			if old.Domain != "" && (old.Domain != domain || old.Original != a.Original) {
				return errors.New("已发布地址不能改变业务身份")
			}
			if old.Expires.After(next.Expires) {
				next.Expires = old.Expires
			}
			next.published = next.published || old.published
		}
		updates[a.Address] = next
	}
	newEntries := 0
	for ip := range updates {
		if _, ok := p.entries[ip]; !ok {
			newEntries++
		}
	}
	if len(p.entries)+newEntries > 8192 {
		return errors.New("映射容量不足")
	}
	for ip, e := range updates {
		p.entries[ip] = e
	}
	return nil
}

func (r *Registry) Confirm(key string, aliases []workeripc.DNSAlias) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pools[key]
	if p == nil || p.retired {
		return errors.New("映射会话已结束")
	}
	for _, a := range aliases {
		e, ok := p.entries[a.Address]
		if !ok || e.Original != a.Original || !r.clock().Before(e.Expires) {
			return errors.New("映射发布已失效")
		}
	}
	for _, a := range aliases {
		e := p.entries[a.Address]
		e.published = true
		p.entries[a.Address] = e
	}
	return nil
}

func (r *Registry) Acquire(key, address string) (Target, func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.pools[key]
	if p == nil || p.retired {
		return Target{}, nil, errors.New("映射会话已结束")
	}
	e, ok := p.entries[address]
	if !ok || !e.published || !r.clock().Before(e.Expires) {
		return Target{}, nil, errors.New("映射不存在、尚未发布或已经过期")
	}
	p.streams++
	var once sync.Once
	return e.Target, func() { once.Do(func() { r.mu.Lock(); p.streams--; r.prune(); r.mu.Unlock() }) }, nil
}

func (r *Registry) KeyForAddress(address netip.Addr) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, p := range r.pools {
		if p.prefix.Contains(address) {
			if p.retired {
				return "", errors.New("映射所属会话已退役")
			}
			return key, nil
		}
	}
	return "", errors.New("没有已登记的映射身份")
}

func (r *Registry) Retire(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.pools[key]; p != nil {
		p.retired = true
	}
	r.prune()
}

func (r *Registry) Reservations(except string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune()
	var out []string
	for key, p := range r.pools {
		if key != except {
			out = append(out, p.prefix.String())
		}
	}
	sort.Strings(out)
	return out
}

func ValidateReservations(values []string) error {
	if len(values) > 256 {
		return errors.New("映射保留池过多")
	}
	for _, s := range values {
		p, e := netip.ParsePrefix(s)
		if e != nil || !ValidPrefix(p) {
			return errors.New("无效映射保留池")
		}
	}
	return nil
}
