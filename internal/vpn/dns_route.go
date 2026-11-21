package vpn

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/splitdns"
	"time"
)

func (m *Manager) PreviewDNS(name, gatewayID string) routing.Decision {
	g, _, s := m.routeSnapshot(gatewayID)
	return routing.DecideDNS(name, gatewayID, g, s.DNSBindings, s.SharedExits...)
}

// SelectMappedDNS is a pure selection step for the shared capture DNS listener.
// The selected session's existing publisher remains responsible for allocation.
func (m *Manager) SelectMappedDNS(packet []byte) (string, func() bool, error) {
	q := new(dns.Msg)
	if q.Unpack(packet) != nil || q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 || q.Question[0].Qclass != dns.ClassINET || q.IsTsig() != nil {
		return "", nil, errors.New("无效 DNS 请求")
	}
	g, sessions, settings := m.routeSnapshot("")
	d := routing.DecideDNS(q.Question[0].Name, "", g, settings.DNSBindings, settings.SharedExits...)
	if d.Action != "vpn" || len(d.Candidates) != 1 {
		return "", nil, errors.New("DNS 归属冲突、离线或未授权")
	}
	c, ok := sessions[d.Candidates[0].ID]
	if !ok || !m.currentRoute(c, c.id) {
		return "", nil, errors.New("DNS 会话已变化")
	}
	return fmt.Sprintf("%p/%d", c.endpoint, c.gen), func() bool {
		if !m.currentRoute(c, c.id) {
			return false
		}
		current := m.PreviewDNS(q.Question[0].Name, "")
		return current.Action == "vpn" && len(current.Candidates) == 1 && current.Candidates[0].ID == c.id && current.Candidates[0].Generation == c.gen && current.Candidates[0].Version == c.version
	}, nil
}

// ExchangeResourceDNS selects exactly one owner before querying its cache.
func (m *Manager) ExchangeResourceDNS(ctx context.Context, packet []byte) ([]byte, error) {
	q := new(dns.Msg)
	if q.Unpack(packet) != nil || q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return nil, errors.New("无效 DNS 请求")
	}
	if q.Question[0].Qclass != dns.ClassINET || q.Question[0].Qtype == dns.TypeAXFR || q.Question[0].Qtype == dns.TypeIXFR || q.IsTsig() != nil {
		return new(dns.Msg).SetRcode(q, dns.RcodeRefused).Pack()
	}
	g, sessions, settings := m.routeSnapshot("")
	d := routing.DecideDNS(q.Question[0].Name, "", g, settings.DNSBindings, settings.SharedExits...)
	if d.Action != "vpn" {
		code := dns.RcodeServerFailure
		if len(d.Owners) == 0 {
			code = dns.RcodeRefused
		}
		return new(dns.Msg).SetRcode(q, code).Pack()
	}
	c := sessions[d.Candidates[0].ID]
	exchanger, ok := c.sess.(DNSExchanger)
	if !ok {
		return new(dns.Msg).SetRcode(q, dns.RcodeServerFailure).Pack()
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	return m.dnsCache.Exchange(ctx, splitdns.Identity{GatewayID: c.id, Generation: c.gen, Version: c.version, Mode: "raw"}, packet, func() bool {
		if !m.currentRoute(c, c.id) {
			return false
		}
		current := m.PreviewDNS(q.Question[0].Name, "")
		return current.Action == "vpn" && current.Candidates[0].ID == c.id && current.Candidates[0].Generation == c.gen && current.Candidates[0].Version == c.version
	}, exchanger.ExchangeDNS)
}

func (s *zjuSession) ExchangeDNS(ctx context.Context, packet []byte) ([]byte, error) {
	q := new(dns.Msg)
	if len(packet) > 65535 || q.Unpack(packet) != nil {
		return nil, errors.New("无效 DNS 请求")
	}
	if s.closed.Load() {
		return nil, errors.New("VPN 会话已结束")
	}
	m, err := s.resolver.ExchangeInternal(ctx, q)
	if err != nil {
		return nil, err
	}
	return m.Pack()
}
