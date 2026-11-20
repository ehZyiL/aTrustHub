package vpn

import (
	"context"
	"errors"
	"fmt"
	"github.com/qy/easyconnect/internal/workeripc"
	"net"
	"net/netip"
	"sync"
)

type AppConnection struct {
	Key       string
	Dial      func(context.Context, string, string) (net.Conn, error)
	Active    func() bool
	DNS       func(context.Context, []byte) ([]byte, error)
	MappedDNS func(context.Context, []byte, string) (workeripc.Message, error)
	Resources *workeripc.ResourceSnapshot
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
	var aliasMu sync.RWMutex
	var aliasPrefix netip.Prefix
	if resolver, ok := sess.(interface {
		ExchangeMappedDNS(context.Context, []byte, string) (workeripc.Message, error)
	}); ok {
		connection.MappedDNS = func(ctx context.Context, packet []byte, prefix string) (workeripc.Message, error) {
			if !active() {
				return workeripc.Message{}, net.ErrClosed
			}
			result, err := resolver.ExchangeMappedDNS(ctx, packet, prefix)
			if !active() {
				return workeripc.Message{}, net.ErrClosed
			}
			if err == nil {
				p, e := netip.ParsePrefix(prefix)
				if e != nil || p != p.Masked() || p.Bits() < 20 || p.Bits() > 24 || !netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(p.Addr()) {
					return workeripc.Message{}, errors.New("无效映射池")
				}
				aliasMu.Lock()
				if aliasPrefix.IsValid() && aliasPrefix != p {
					aliasMu.Unlock()
					return workeripc.Message{}, errors.New("会话映射池不能变更")
				}
				aliasPrefix = p
				aliasMu.Unlock()
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
		host, _, _ := net.SplitHostPort(address)
		ip, _ := netip.ParseAddr(host)
		aliasMu.RLock()
		mapped := aliasPrefix.IsValid() && aliasPrefix.Contains(ip)
		aliasMu.RUnlock()
		c, err := m.dialBound(ctx, network, address, id, gen, sess, mapped)
		if !active() {
			if c != nil {
				_ = c.Close()
			}
			return nil, net.ErrClosed
		}
		return c, err
	}
	return connection, nil
}
