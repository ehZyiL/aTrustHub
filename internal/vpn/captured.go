package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/qy/easyconnect/internal/routing"
	"github.com/qy/easyconnect/internal/workeripc"
)

type OriginalDialFunc = func(context.Context, string, string) (net.Conn, error)
type originalDialContextKey struct{}

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
	if _, ok := ctx.Value(originalDialContextKey{}).(OriginalDialFunc); !ok {
		return nil, errors.New("系统捕获缺少可信原出口")
	}
	destination, err := netip.ParseAddrPort(address)
	if err != nil || !destination.Addr().Is4() || network != "tcp" && network != "tcp4" {
		return nil, errors.New("系统捕获目前仅支持 IPv4 TCP")
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
	return &mappedConn{Conn: conn, release: release}, nil
}
