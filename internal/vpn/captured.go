package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/routing"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

type OriginalDialFunc = func(context.Context, string, string) (net.Conn, error)
type originalDialContextKey struct{}
type capturedOwnershipKey struct{}

// Capture guards retain attribution even when a configured gateway is deleted.
// They never authorize a connection or override an explicit direct policy.
func WithCapturedOwnership(ctx context.Context, ranges []netpolicy.Range) context.Context {
	return context.WithValue(ctx, capturedOwnershipKey{}, ranges)
}

// WithOriginalDial is supplied only by the trusted capture adapter. Public
// SOCKS requests cannot provide an egress capability or a mapping identity.
func WithOriginalDial(ctx context.Context, dial OriginalDialFunc) context.Context {
	return context.WithValue(ctx, originalDialContextKey{}, dial)
}

func originalRouteDial(ctx context.Context, network, address string) (net.Conn, error) {
	if dial, ok := ctx.Value(originalDialContextKey{}).(OriginalDialFunc); ok {
		if dial == nil {
			return nil, errors.New("接管原出口未就绪")
		}
		return dial(ctx, network, address)
	}
	return directDial(ctx, network, address)
}

// DialCaptured accepts only IP destinations observed by the private helper.
// A synthetic destination must have a published identity in the shared pool.
func (m *Manager) DialCaptured(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, errors.New("系统 TCP 捕获要求 IPv4 TCP")
	}
	return m.dialCaptured(ctx, network, address)
}

// DialCapturedUDP is the private datagram path. Until the platform exposes a
// trusted original UDP egress, only authorized VPN exits can be used.
func (m *Manager) DialCapturedUDP(ctx context.Context, address string) (net.Conn, error) {
	return m.dialCaptured(ctx, "udp4", address)
}

func (m *Manager) dialCaptured(ctx context.Context, network, address string) (net.Conn, error) {
	if _, ok := ctx.Value(originalDialContextKey{}).(OriginalDialFunc); !ok {
		return nil, errors.New("系统捕获缺少可信原出口")
	}
	destination, err := netip.ParseAddrPort(address)
	if err != nil || !destination.Addr().Is4() || destination.Port() == 0 {
		return nil, errors.New("系统捕获要求 IPv4 目标及有效端口")
	}
	request := routing.Request{Network: network, Address: address, Entry: "系统 TUN"}
	if !netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(destination.Addr()) {
		return m.dialRoute(ctx, request, nil)
	}
	key, err := m.mappings.KeyForAddress(destination.Addr())
	if err != nil {
		return nil, err
	}
	target, release, err := m.mappings.Acquire(key, destination.Addr().String())
	if err != nil {
		return nil, err
	}
	_, sessions, _ := m.routeSnapshot(target.GatewayID)
	session, ok := sessions[target.GatewayID]
	if !ok || fmt.Sprintf("%p/%d", session.endpoint, session.gen) != target.Key || session.gen != target.Generation || session.version != target.Version || !m.currentRoute(session, target.GatewayID) {
		release()
		return nil, net.ErrClosed
	}
	_, port, _ := net.SplitHostPort(address)
	request.GatewayID, request.Mapped = target.GatewayID, true
	request.OriginalAddress = net.JoinHostPort(target.Domain, port)
	conn, err := m.dialRoute(ctx, request, &session)
	if err != nil {
		release()
		return nil, err
	}
	if udp, ok := conn.(*scopedUDPConn); ok {
		go func() { <-udp.done; release() }()
	}
	return &mappedConn{Conn: conn, release: release}, nil
}

func checkCapturedDirect(ctx context.Context, decision routing.Decision) error {
	if len(decision.Owners) != 0 || decision.RuleID != "" {
		return nil
	}
	destination, err := netip.ParseAddrPort(decision.Target)
	if err != nil {
		return nil
	}
	if ranges, ok := ctx.Value(capturedOwnershipKey{}).([]netpolicy.Range); ok {
		for _, r := range ranges {
			lo, hi, err := r.Addresses()
			if err == nil && lo.BitLen() == destination.Addr().BitLen() && lo.Compare(destination.Addr()) <= 0 && hi.Compare(destination.Addr()) >= 0 {
				return errors.New("该捕获资源的网关已移除，禁止回退原网络")
			}
		}
	}
	return nil
}
