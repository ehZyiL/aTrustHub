package vpn

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/dnsmapping"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/routing"
	"github.com/qy/easyconnect/internal/workeripc"
	"net"
	"net/netip"
	"sync"
)

type AppConnection struct {
	Key              string
	Identity         dnsmapping.Identity
	SelectDNS        func([]byte) (string, func() bool, error)
	Dial             func(context.Context, string, string) (net.Conn, error)
	Active           func() bool
	DNS              func(context.Context, []byte) ([]byte, error)
	MappedDNS        func(context.Context, []byte, string) (workeripc.Message, error)
	ConfirmAliases   func([]workeripc.DNSAlias) error
	BeginPublication func(string) (func(), error)
	CheckPublication func(string) error
	MappingPrefix    func() (string, error)
	Resources        *workeripc.ResourceSnapshot
	ReservedPools    []string
	AliasNetworks    []netpolicy.Range
}

// LocalAppDialer binds a launcher to the current session generation. A later
// reconnect never silently redirects an old application's lease to a new VPN.
// It reuses the existing Session dialer, without an unauthenticated public hop.
func (m *Manager) LocalAppDialer(id string) (dial func(context.Context, string, string) (net.Conn, error), active func() bool, err error) {
	c, err := m.LocalAppConnection(id)
	return c.Dial, c.Active, err
}

func (m *Manager) LocalAppConnection(id string) (AppConnection, error) {
	var connection AppConnection
	m.mu.RLock()
	ep := m.points[id]
	if ep == nil || ep.state != StateOnline || ep.sess == nil {
		m.mu.RUnlock()
		return connection, errors.New("请先登录所选 VPN 接入点")
	}
	gen, sess := ep.gen, ep.sess
	m.mu.RUnlock()
	connection.Key = fmt.Sprintf("%p/%d", ep, gen)
	active := func() bool {
		m.mu.RLock()
		defer m.mu.RUnlock()
		cur := m.points[id]
		return !m.closed && cur == ep && cur.gen == gen && cur.state == StateOnline && cur.sess != nil
	}
	connection.Active = active
	connection.Resources = sess.Info().Resources
	connection.Resources = cloneResources(connection.Resources)
	connection.ReservedPools = m.mappings.Reservations(connection.Key)
	connection.AliasNetworks = m.aliasNetworks()
	identity := dnsmapping.Identity{Key: connection.Key, GatewayID: id, Generation: gen, Version: resourceVersion(connection.Resources)}
	connection.Identity = identity
	connection.MappingPrefix = func() (string, error) { return m.mappings.Prefix(identity) }
	connection.CheckPublication = func(prefix string) error {
		if !active() {
			return net.ErrClosed
		}
		return m.mappings.CheckPrefix(identity, prefix)
	}
	connection.SelectDNS = m.SelectMappedDNS
	connection.BeginPublication = func(prefix string) (func(), error) {
		if !active() {
			return nil, net.ErrClosed
		}
		finish, err := m.mappings.Begin(identity, prefix, m.aliasNetworks())
		if err != nil {
			return nil, err
		}
		if !active() {
			m.mappings.Retire(connection.Key)
			finish()
			return nil, net.ErrClosed
		}
		return finish, nil
	}
	connection.ConfirmAliases = func(aliases []workeripc.DNSAlias) error {
		if !active() {
			return net.ErrClosed
		}
		return m.mappings.Confirm(connection.Key, aliases)
	}
	if resolver, ok := sess.(interface {
		ExchangeMappedDNS(context.Context, []byte, string) (workeripc.Message, error)
	}); ok {
		connection.MappedDNS = func(ctx context.Context, packet []byte, prefix string) (workeripc.Message, error) {
			if !active() {
				return workeripc.Message{}, net.ErrClosed
			}
			q := new(dns.Msg)
			if q.Unpack(packet) != nil || len(q.Question) != 1 {
				return workeripc.Message{}, errors.New("无效 DNS 请求")
			}
			name, e := routing.NormalizeHost(q.Question[0].Name)
			if e != nil {
				return workeripc.Message{}, e
			}
			finish, e := connection.BeginPublication(prefix)
			if e != nil {
				return workeripc.Message{}, e
			}
			defer finish()
			result, err := resolver.ExchangeMappedDNS(ctx, packet, prefix)
			if !active() {
				m.mappings.Retire(connection.Key)
				return workeripc.Message{}, net.ErrClosed
			}
			if err == nil {
				err = m.mappings.Stage(connection.Key, name, result.DNSAliases)
			}
			return result, err
		}
	}
	if resolver, ok := sess.(interface {
		ExchangeCaptureDNS(context.Context, []byte) ([]byte, error)
	}); ok {
		connection.DNS = func(ctx context.Context, packet []byte) ([]byte, error) {
			if !active() {
				return nil, net.ErrClosed
			}
			result, err := resolver.ExchangeCaptureDNS(ctx, packet)
			if !active() {
				return nil, net.ErrClosed
			}
			return result, err
		}
	}
	connection.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if !active() {
			return nil, errors.New("该软件所属的 VPN 会话已结束，请重新启动接管")
		}
		host, port, _ := net.SplitHostPort(address)
		ip, _ := netip.ParseAddr(host)
		mapped := netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(ip)
		var release func()
		original := ""
		if mapped {
			target, done, err := m.mappings.Acquire(connection.Key, ip.String())
			if err != nil {
				return nil, err
			}
			release = done
			original = net.JoinHostPort(target.Domain, port)
		}
		c, err := m.dialBound(ctx, network, address, id, gen, ep, mapped, original)
		if !active() {
			if c != nil {
				_ = c.Close()
			}
			if release != nil {
				release()
			}
			return nil, net.ErrClosed
		}
		if release != nil {
			if err != nil {
				release()
			} else {
				c = &mappedConn{Conn: c, release: release}
			}
		}
		return c, err
	}
	return connection, nil
}

func (m *Manager) aliasNetworks() []netpolicy.Range {
	var resources []netpolicy.Range
	for _, g := range m.ResourceGateways() {
		if g.Current != nil {
			for _, r := range g.Current.IPRules {
				resources = append(resources, netpolicy.Range{Min: r.Min, Max: r.Max})
			}
			for _, r := range g.Current.StaticDNS {
				for _, ip := range r.Addresses {
					resources = append(resources, netpolicy.Range{Min: ip, Max: ip})
				}
			}
		}
	}
	return resources
}

type mappedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *mappedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *mappedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func (c *mappedConn) FlowResult() workeripc.FlowResult {
	return workeripc.ConnectionResult(c.Conn, nil)
}
