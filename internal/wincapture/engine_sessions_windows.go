package wincapture

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/dnsmapping"
)

// register adds a gateway to the existing adapter. It never restarts the stack
// or replaces another gateway's mapping table or application identities.
func (e *engine) register(id string, config Config) (string, error) {
	if !validID(id) {
		return "", errors.New("VPN 接管会话标识无效")
	}
	if err := config.validate(); err != nil {
		return "", err
	}
	resources, err := ResourcePrefixes(config.Networks)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
	gateways, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", config.Gateway)
	cancel()
	if err != nil || len(gateways) == 0 {
		return "", errors.New("无法确认新增 VPN 网关的原出口")
	}
	ctx, cancel = context.WithTimeout(e.ctx, 20*time.Second)
	unlock, err := networkTransaction(ctx)
	cancel()
	if err != nil {
		return "", err
	}
	defer unlock()
	routes, err := routeRows()
	if err != nil {
		return "", err
	}
	occupied := []netip.Prefix{e.adapter}
	for _, route := range routes {
		if route.Prefix.Bits() >= 15 {
			occupied = append(occupied, route.Prefix)
		}
		for _, resource := range resources {
			if route.Interface != e.index && route.Prefix.Bits() >= resource.Bits() && route.Prefix.Overlaps(resource) {
				return "", errors.New("新增 VPN 资源与现有路由冲突")
			}
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil && prefix.Addr().Is4() {
			occupied = append(occupied, netip.PrefixFrom(prefix.Addr(), 32))
		}
	}
	for _, raw := range config.ReservedPools {
		occupied = append(occupied, netip.MustParsePrefix(raw))
	}
	occupied = append(occupied, resources...)
	e.mu.Lock()
	for _, session := range e.sessions {
		occupied = append(occupied, session.aliases)
		occupied = append(occupied, session.resources...)
	}
	e.mu.Unlock()
	aliases, err := dnsmapping.Choose(occupied, config.AliasNetworks)
	if err != nil {
		return "", err
	}
	if err = e.registerPrepared(id, config, aliases, resources, gateways); err != nil {
		return "", err
	}
	return aliases.String(), nil
}

func (e *engine) registerPrepared(id string, config Config, aliases netip.Prefix, resources []netip.Prefix, gateways []netip.Addr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !validID(id) || e.sessions[id] != nil || len(e.sessions) >= 16 {
		return errors.New("VPN 接管会话标识已使用或映射池已满")
	}
	if !dnsmapping.ValidPrefix(aliases) || aliases.Overlaps(e.adapter) {
		return errors.New("VPN 接管映射池无效")
	}
	allResources := append([]netip.Prefix(nil), resources...)
	allGateways := append([]netip.Addr(nil), gateways...)
	for _, session := range e.sessions {
		if aliases.Overlaps(session.aliases) {
			return errors.New("VPN 会话映射池重叠")
		}
		allResources = append(allResources, session.resources...)
		allGateways = append(allGateways, session.gateways...)
		// Until the shared DNS policy transaction is installed, refuse an
		// overlapping namespace rather than let NRPT choose a random owner.
		if !session.retired {
			for _, a := range config.Domains {
				for _, b := range session.config.Domains {
					if dns.IsSubDomain(a+".", b+".") || dns.IsSubDomain(b+".", a+".") {
						return errors.New("接管 DNS 后缀与另一网关重叠，请先使用指定网关代理")
					}
				}
			}
		}
	}
	for _, p := range allResources {
		if p.Overlaps(e.adapter) || p.Overlaps(aliases) {
			return errors.New("VPN 资源覆盖了接管网卡或映射池")
		}
		for _, session := range e.sessions {
			if p.Overlaps(session.aliases) {
				return errors.New("VPN 资源覆盖了已有会话映射池")
			}
		}
		for _, gateway := range allGateways {
			if p.Contains(gateway.Unmap()) {
				return errors.New("VPN 资源覆盖了网关控制连接")
			}
		}
	}
	undo, err := e.installRoute(aliases)
	if err != nil {
		return errors.Join(err, callUndo(undo))
	}
	e.aliasUndo = append(e.aliasUndo, undo)
	ctx, cancel := context.WithCancel(e.ctx)
	session := &captureSession{config: cloneConfig(config), aliases: aliases, resources: resources, gateways: gateways,
		mappings: map[netip.Addr]aliasEntry{}, issued: map[netip.Addr]netip.Addr{}, ctx: ctx, cancel: cancel}
	for _, p := range resources {
		session.rules.install = append(session.rules.install, func() (func() error, error) {
			return e.shared.acquire("route/"+p.String(), func() (func() error, error) { return e.installRoute(p) })
		})
	}
	if len(config.Domains) > 0 {
		session.rules.install = append(session.rules.install, func() (func() error, error) {
			return installNRPT(e.ctx, id, config.Domains, e.dnsAddress.String())
		})
	}
	e.sessions[id] = session
	return nil
}

func callUndo(undo func() error) error {
	if undo != nil {
		return undo()
	}
	return nil
}

func (e *engine) unregister(id string) error {
	e.mu.Lock()
	session := e.sessions[id]
	if session == nil {
		e.mu.Unlock()
		return nil
	}
	session.retired = true
	session.cancel()
	var apps []string
	for appID, app := range e.apps {
		if app.session == id {
			apps = append(apps, appID)
		}
	}
	e.mu.Unlock()
	var result error
	for _, appID := range apps {
		result = errors.Join(result, e.detach(id, appID))
	}
	// Retain the alias route and immutable identity until this helper drains.
	// There are at most sixteen pools; exhaustion fails without reusing one.
	return errors.Join(result, session.rules.Disable())
}

func (e *engine) validateAppTarget(sessionID string, destination netip.Addr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if session := e.sessions[sessionID]; session == nil || session.retired {
		return errors.New("VPN 接管会话已结束")
	}
	if e.adapter.Contains(destination) {
		return errors.New("不能转发到接管网卡")
	}
	for id, session := range e.sessions {
		if !session.aliases.Contains(destination) {
			continue
		}
		if id != sessionID || session.retired {
			return errors.New("映射属于其他 VPN 会话")
		}
		entry, ok := session.mappings[destination]
		if !ok || !time.Now().Before(entry.expires) {
			return errors.New("DNS 映射已失效")
		}
		return nil
	}
	if netip.MustParsePrefix("198.19.0.0/16").Contains(destination) {
		return errors.New("未知 DNS 映射地址")
	}
	return nil
}
