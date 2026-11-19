package proxy

import (
	"context"
	"errors"
	"net"
	"time"

	xproxy "golang.org/x/net/proxy"
)

type socksHandshake interface {
	DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
}

// SOCKSDialer reuses x/net's SOCKS handshake while returning the original TCP
// transport. Its usual DialContext result embeds net.Conn and hides CloseWrite,
// which otherwise prevents a relay from propagating a TCP half-close.
type SOCKSDialer struct {
	address   string
	handshake socksHandshake
}

func NewSOCKSDialer(address string, auth *xproxy.Auth) (*SOCKSDialer, error) {
	d, err := xproxy.SOCKS5("tcp", address, auth, nil)
	if err != nil {
		return nil, err
	}
	h, ok := d.(socksHandshake)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not support handshaking an existing connection")
	}
	return &SOCKSDialer{address: address, handshake: h}, nil
}

func (d *SOCKSDialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	if _, err = d.handshake.DialWithConn(ctx, c, network, target); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
