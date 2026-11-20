package capture

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/qy/easyconnect/internal/dnsmapping"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/packetstack"
	"github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/resolved"
	"github.com/qy/easyconnect/internal/workeripc"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

type systemPool struct {
	Prefix  netip.Prefix
	Entries map[netip.Addr]aliasRecord
	Alias   *sharedAliases
	Retired bool
	Flows   int
}

type systemRuntime struct {
	owner    string
	run      commandFunc
	path     string
	aliasDir string
	device   *systemDevice
	stack    *packetstack.Stack
	original *proxy.Server
	state    SystemState
	upstream Upstream
	dnsAddr  string
	dial     *proxy.SOCKSDialer
	journal  systemJournal
	unlock   func()
	ctx      context.Context
	cancel   context.CancelFunc

	mu      sync.Mutex
	routes  map[netip.Prefix]bool
	pools   map[string]*systemPool
	failure error
	slots   chan struct{}
	closed  sync.Once
}

func chooseSystemSource(state kernelState) (netip.Addr, error) {
	for i := range 256 {
		ip := netip.AddrFrom4([4]byte{198, 18, byte(i), 1})
		occupied := false
		for _, route := range state.routes {
			if prefix, ok := linuxRoutePrefix(route); ok && prefix.Bits() >= 15 && prefix.Contains(ip) {
				occupied = true
				break
			}
		}
		if !occupied {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("capture: no free system TUN source address")
}

func newSystemRuntime(ctx context.Context, run commandFunc, path, owner string, c SystemConfig, kernel kernelState, reservations map[string]int64) (*systemRuntime, error) {
	for _, rule := range kernel.rules {
		if mark, present := number(rule["fwmark"]); present && mark == 0 {
			mask, explicit := number(rule["fwmask"])
			if !explicit || mask == ^uint32(0) {
				return nil, errors.New("capture: an exact unmarked policy needs an original-egress adapter")
			}
		}
	}
	allocation, err := allocateRouting(kernel)
	if err != nil {
		return nil, err
	}
	source, err := chooseSystemSource(kernel)
	if err != nil {
		return nil, err
	}
	dialer, err := proxy.NewSOCKSDialer(c.Upstream.Address, &xproxy.Auth{User: c.Upstream.Username, Password: c.Upstream.Password})
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	r := &systemRuntime{owner: owner, run: run, path: path, upstream: c.Upstream, dnsAddr: c.DNSAddress, dial: dialer,
		ctx: life, cancel: cancel, routes: map[netip.Prefix]bool{}, pools: map[string]*systemPool{}, slots: make(chan struct{}, 512),
		journal: systemJournal{Routes: systemRoutes{routingAllocation: allocation, ID: randomID(), Source: source}, Pools: reservations}}
	r.device, err = openSystemDevice(ctx, run, r.journal.Routes.ID, source)
	if err != nil {
		cancel()
		return nil, err
	}
	r.stack = packetstack.New(life, r.device, r)
	if err = r.stack.Start(); err == nil {
		err = r.startOriginal()
	}
	if err != nil {
		return nil, errors.Join(err, r.close())
	}
	return r, nil
}

func (r *systemRuntime) installRule(ctx context.Context) error {
	if err := r.journal.save(r.path); err != nil {
		return err
	}
	return r.journal.Routes.addRule(ctx, r.run)
}

func (r *systemRuntime) startOriginal() error {
	password := randomID() + randomID()
	r.original = proxy.New(proxy.Options{Addr: "127.0.0.1:0", Auth: &proxy.Auth{Username: "original", Credential: password},
		Context: r.ctx, SOCKSOnly: true, Dial: r.originalDial})
	if err := r.original.Start(); err != nil {
		return err
	}
	r.state.Original = Upstream{Address: r.original.Addr().String(), Username: "original", Password: password}
	return nil
}

func (r *systemRuntime) originalDial(ctx context.Context, network, address string) (net.Conn, error) {
	target, err := netip.ParseAddrPort(address)
	if err != nil || !target.Addr().Is4() || (network != "tcp" && network != "tcp4") {
		return nil, errors.New("capture: invalid original egress target")
	}
	r.mu.Lock()
	allowed := r.containsResource(target.Addr())
	if !allowed {
		now, clockErr := bootNow()
		if clockErr != nil {
			r.mu.Unlock()
			return nil, clockErr
		}
		for _, pool := range r.pools {
			for _, entry := range pool.Entries {
				if !pool.Retired && entry.Original == target.Addr().String() && entry.Expires > now {
					allowed = true
					break
				}
			}
		}
	}
	r.mu.Unlock()
	if !allowed {
		return nil, errors.New("capture: original egress target outside system resource routes")
	}
	dialer := net.Dialer{Control: func(_, _ string, socket syscall.RawConn) error {
		var markErr error
		err := socket.Control(func(fd uintptr) {
			markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(r.journal.Routes.Mark))
		})
		return errors.Join(err, markErr)
	}}
	return dialer.DialContext(ctx, "tcp4", address)
}

func (r *systemRuntime) containsResource(addr netip.Addr) bool {
	if netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(addr) {
		return false
	}
	for prefix := range r.routes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (r *systemRuntime) acquireTarget(addr netip.Addr) (func(), error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.containsResource(addr) {
		return func() {}, nil
	}
	now, err := bootNow()
	if err != nil {
		return nil, err
	}
	for _, pool := range r.pools {
		if pool.Prefix.Contains(addr) {
			if pool.Retired || now >= pool.Entries[addr].Expires {
				break
			}
			pool.Flows++
			return func() {
				r.mu.Lock()
				pool.Flows--
				r.mu.Unlock()
			}, nil
		}
	}
	return nil, errors.New("capture: system target or DNS mapping is no longer active")
}

func (r *systemRuntime) NewConnection(_ context.Context, incoming net.Conn, metadata M.Metadata) error {
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return errors.New("capture: system connection limit reached")
	}
	release, err := r.acquireTarget(metadata.Destination.Addr)
	if err != nil {
		return err
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
	upstream, err := r.dial.DialContext(ctx, "tcp", metadata.Destination.String())
	cancel()
	if err != nil {
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(r.ctx, func() { incoming.Close(); upstream.Close() })
	defer stop()
	proxy.Relay(incoming, upstream)
	return nil
}

func (r *systemRuntime) NewPacketConnection(_ context.Context, incoming N.PacketConn, metadata M.Metadata) error {
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return errors.New("capture: system connection limit reached")
	}
	release, err := r.acquireTarget(metadata.Destination.Addr)
	if err != nil {
		return err
	}
	defer release()
	upstream, err := r.dial.DialDatagramContext(r.ctx, metadata.Destination.String())
	if err != nil {
		return err
	}
	packetstack.RelayUDP(r.ctx, incoming, metadata.Destination, upstream)
	return nil
}

func (r *systemRuntime) NewError(_ context.Context, err error) {
	r.mu.Lock()
	r.failure = err
	r.mu.Unlock()
	r.cancel()
}

// apply extends resource guards before acknowledging the new worker snapshot.
// Previously captured resources stay guarded until the mode is stopped.
func (r *systemRuntime) apply(ctx context.Context, config SystemConfig, foreign []string, sharedPools ...map[string]*sharedAliases) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx != nil && r.ctx.Err() != nil {
		return net.ErrClosed
	}
	if config.Upstream.Address != r.upstream.Address || config.Upstream.Username != r.upstream.Username ||
		config.Upstream.Password != r.upstream.Password || config.DNSAddress != r.dnsAddr {
		return errors.New("capture: system upstream changed")
	}
	if err := r.prune(ctx); err != nil {
		return err
	}
	state, err := snapshot(ctx, r.run)
	if err != nil {
		return err
	}
	shared := map[string]*sharedAliases{}
	if len(sharedPools) > 0 {
		shared = sharedPools[0]
	}
	state, err = r.sharedAliasState(ctx, state, shared)
	if err != nil {
		return err
	}
	desired := maps.Clone(r.routes)
	var resourceRanges []netpolicy.Range
	var gateways []netip.Addr
	domains := map[string]bool{}
	if r.journal.DNS != nil {
		for _, domain := range r.journal.DNS.Config.Domains {
			domains[domain] = true
		}
	}
	for _, resource := range config.Resources {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", resource.Gateway)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("capture: cannot verify upstream gateway address for %s", resource.ID)
		}
		gateways = append(gateways, ips...)
		resourceRanges = append(resourceRanges, resource.Networks...)
		for _, domain := range resource.Domains {
			domains[domain] = true
		}
	}
	prefixes, err := netpolicy.ResourcePrefixes(resourceRanges)
	if err != nil {
		return err
	}
	for _, prefix := range prefixes {
		desired[prefix] = true
	}
	for prefix := range desired {
		for _, gateway := range gateways {
			if prefix.Contains(gateway.Unmap()) {
				return errors.New("capture: system routes would capture the VPN control connection")
			}
		}
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	reserved := append(slices.Clone(config.Reserved), foreign...)
	for prefix, expiry := range r.journal.Pools {
		if expiry > now && !sharedPrefix(shared, prefix) {
			reserved = append(reserved, prefix)
		}
	}
	for _, pool := range r.pools {
		reserved = append(reserved, pool.Prefix.String())
	}
	pools := maps.Clone(r.pools)
	// A helper restart cannot safely restore old mapping identities or grants.
	// Keep their unexpired prefixes routed to the rejecting packet stack so a
	// client with a cached synthetic address cannot fall through to another VPN.
	for raw, expiry := range r.journal.Pools {
		if expiry <= now {
			delete(r.journal.Pools, raw)
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !dnsmapping.ValidPrefix(prefix) {
			return errors.New("capture: invalid retired system DNS pool")
		}
		desired[prefix] = true
	}
	active := make(map[string]string)
	for _, resource := range config.Resources {
		if resource.Guard || len(resource.Domains) == 0 {
			continue
		}
		pool := pools[resource.ID]
		if pool != nil && pool.Retired {
			return errors.New("capture: retired DNS scope cannot be reactivated")
		}
		if pool != nil && resource.RequiredPrefix != "" && pool.Prefix.String() != resource.RequiredPrefix {
			return errors.New("capture: worker DNS pool cannot change; reconnect this gateway before changing capture modes")
		}
		alias := shared[resource.ID]
		if pool != nil && pool.Alias != alias {
			return errors.New("capture: system DNS lease identity cannot change")
		}
		if pool == nil {
			required := resource.RequiredPrefix
			if alias != nil {
				required = alias.route.Prefix
			}
			raw, err := chooseAliasPrefix(state, config.AliasRanges, reserved, required)
			if err != nil {
				return err
			}
			if resource.RequiredPrefix != "" && raw != resource.RequiredPrefix {
				return errors.New("capture: worker DNS pool cannot change; reconnect this gateway before changing capture modes")
			}
			prefix := netip.MustParsePrefix(raw)
			pool = &systemPool{Prefix: prefix, Entries: make(map[netip.Addr]aliasRecord), Alias: alias}
			if alias != nil {
				for addr, entry := range alias.journal.Entries {
					pool.Entries[netip.MustParseAddr(addr)] = entry
				}
			}
			pools[resource.ID] = pool
			desired[prefix] = true
			reserved = append(reserved, raw)
		}
		active[resource.ID] = pool.Prefix.String()
	}
	if len(desired) > 2048 {
		return errors.New("capture: too many accumulated resource routes")
	}
	if err := r.journal.Routes.checkOverlap(state, slices.Collect(maps.Keys(desired))); err != nil {
		return err
	}
	// Journal imported lifetimes before removing original-destination recovery
	// tables. A crash can reserve/reject cached addresses, never reassign them.
	if err := r.reserveSharedAliases(shared); err != nil {
		return err
	}
	undo, err := r.suspendSharedAliases(ctx, shared)
	if err != nil {
		return err
	}
	if err := r.install(ctx, desired, slices.Sorted(maps.Keys(domains))); err != nil {
		return errors.Join(err, undo())
	}
	for id, pool := range pools {
		pool.Retired = active[id] == ""
	}
	r.routes, r.pools, r.state.Prefixes = desired, pools, active
	return nil
}

func (r *systemRuntime) install(ctx context.Context, desired map[netip.Prefix]bool, domains []string) (err error) {
	owned := r.journal.Routes
	var added []netip.Prefix
	defer func() {
		if err == nil {
			return
		}
		undo, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for i := len(added) - 1; i >= 0; i-- {
			err = errors.Join(err, owned.changeRoute(undo, r.run, "del", added[i]))
		}
	}()
	for prefix := range desired {
		if !r.routes[prefix] {
			if err := owned.changeRoute(ctx, r.run, "add", prefix); err != nil {
				return err
			}
			added = append(added, prefix)
		}
	}
	after, err := snapshot(ctx, r.run)
	if err != nil {
		return err
	}
	if err := owned.verify(after, desired); err != nil {
		return err
	}
	if err := owned.checkOverlap(after, slices.Collect(maps.Keys(desired))); err != nil {
		return err
	}
	if len(domains) == 0 {
		return nil
	}
	if r.journal.DNS != nil {
		next, err := resolved.UpdateDomains(ctx, resolved.Command(r.run), *r.journal.DNS, domains)
		if err == nil {
			r.journal.DNS = &next
		}
		return err
	}
	lease, err := resolved.Prepare(ctx, resolved.Command(r.run), resolved.Config{Address: r.dnsAddr, Domains: domains})
	if err != nil {
		return err
	}
	next := r.journal
	next.DNS = lease
	if err := next.save(r.path); err != nil {
		return err
	}
	r.journal.DNS = lease
	if err := resolved.Install(ctx, resolved.Command(r.run), *lease); err != nil {
		undo, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanup := resolved.Remove(undo, resolved.Command(r.run), *lease)
		if cleanup == nil {
			r.journal.DNS = nil
			cleanup = r.journal.save(r.path)
		}
		return errors.Join(err, cleanup)
	}
	return nil
}

func (r *systemRuntime) prune(ctx context.Context) error {
	now, err := bootNow()
	if err != nil {
		return err
	}
	for id, pool := range r.pools {
		if !pool.Retired || pool.Flows != 0 || r.journal.Pools[pool.Prefix.String()] > now {
			continue
		}
		if err := r.journal.Routes.changeRoute(ctx, r.run, "del", pool.Prefix); err != nil {
			return err
		}
		delete(r.routes, pool.Prefix)
		delete(r.pools, id)
	}
	for raw, expiry := range r.journal.Pools {
		prefix, parseErr := netip.ParsePrefix(raw)
		if parseErr != nil || !dnsmapping.ValidPrefix(prefix) {
			return errors.New("capture: invalid retired system DNS pool")
		}
		if expiry > now || r.poolsContain(prefix) {
			continue
		}
		if r.routes[prefix] {
			if err := r.journal.Routes.changeRoute(ctx, r.run, "del", prefix); err != nil {
				return err
			}
			delete(r.routes, prefix)
		}
		delete(r.journal.Pools, raw)
		if err := r.journal.save(r.path); err != nil {
			return err
		}
	}
	return nil
}

func (r *systemRuntime) poolsContain(prefix netip.Prefix) bool {
	for _, pool := range r.pools {
		if pool.Prefix == prefix {
			return true
		}
	}
	return false
}

func (r *systemRuntime) publish(id string, aliases []workeripc.DNSAlias) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	pool := r.pools[id]
	if pool == nil || pool.Retired || pool.Alias != nil && pool.Alias.owner == "" || len(aliases) > 32 {
		return errors.New("capture: no active system DNS scope")
	}
	now, err := bootNow()
	if err != nil {
		return err
	}
	entries := maps.Clone(pool.Entries)
	next := r.journal
	next.Pools = maps.Clone(r.journal.Pools)
	if next.Pools == nil {
		next.Pools = map[string]int64{}
	}
	for prefix, expires := range next.Pools {
		if expires <= now {
			delete(next.Pools, prefix)
		}
	}
	for _, alias := range aliases {
		addr, e1 := netip.ParseAddr(alias.Address)
		target, e2 := netip.ParseAddr(alias.Original)
		if e1 != nil || !pool.Prefix.Contains(addr) || e2 != nil || !target.Is4() || !target.IsGlobalUnicast() ||
			target.IsLinkLocalUnicast() || netip.MustParsePrefix("198.18.0.0/15").Contains(target) || alias.TTL == 0 || alias.TTL > 60 {
			return errors.New("capture: invalid system DNS mapping")
		}
		old := entries[addr]
		if old.Original != "" && old.Original != alias.Original {
			return errors.New("capture: published DNS identity cannot be changed")
		}
		expiry := max(old.Expires, now+int64((time.Duration(alias.TTL)+2)*time.Second))
		entries[addr] = aliasRecord{Original: alias.Original, Expires: expiry}
		next.Pools[pool.Prefix.String()] = max(next.Pools[pool.Prefix.String()], expiry+int64(aliasRetireGrace))
	}
	if len(entries) > 4096 {
		return errors.New("capture: system DNS pool is full")
	}
	if len(aliases) > 0 {
		if err := next.save(r.path); err != nil {
			return err
		}
		r.journal.Pools = next.Pools
		if pool.Alias != nil {
			journal := pool.Alias.journal
			journal.Entries = make(map[string]aliasRecord, len(entries))
			for addr, entry := range entries {
				journal.Entries[addr.String()] = entry
			}
			if err := saveAliasJournal(r.aliasDir, journal); err != nil {
				return err
			}
			pool.Alias.journal = journal
		}
	}
	pool.Entries = entries
	return nil
}

func (r *systemRuntime) verify(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx != nil && r.ctx.Err() != nil {
		return net.ErrClosed
	}
	if r.failure != nil {
		return r.failure
	}
	if err := r.prune(ctx); err != nil {
		return err
	}
	state, err := snapshot(ctx, r.run)
	if err != nil {
		return err
	}
	if err := r.journal.Routes.verify(state, r.routes); err != nil {
		return err
	}
	if err := r.journal.Routes.checkOverlap(state, slices.Collect(maps.Keys(r.routes))); err != nil {
		return err
	}
	if r.journal.DNS != nil {
		return resolved.Verify(ctx, resolved.Command(r.run), *r.journal.DNS)
	}
	return nil
}

func (r *systemRuntime) close() error {
	var err error
	r.closed.Do(func() {
		r.cancel()
		if r.original != nil {
			err = errors.Join(err, r.original.Close())
		}
		err = errors.Join(err, r.device.Close(), r.stack.Close())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return errors.Join(err, recoverSystemJournal(ctx, r.run, r.path))
}
