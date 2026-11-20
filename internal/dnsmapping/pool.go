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
		free := true
		for _, used := range occupied {
			if used.Overlaps(p) {
				free = false
				break
			}
		}
		for _, resource := range resources {
			if overlaps(p, resource) {
				free = false
				break
			}
		}
		if free {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("没有空闲的 DNS 映射池，请保留显式代理或等待旧映射退役")
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
