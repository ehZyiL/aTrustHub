package packetstack

import (
	"context"
	"net"

	"github.com/ehZyiL/connect-hub/internal/proxy"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// RelayUDP bridges the pinned capture tuple to the authenticated helper link.
func RelayUDP(ctx context.Context, packets N.PacketConn, destination M.Socksaddr, upstream net.Conn) {
	proxy.RelayDatagrams(ctx, &packetStream{PacketConn: packets, destination: destination}, upstream)
}

type packetStream struct {
	N.PacketConn
	destination M.Socksaddr
}

func (p *packetStream) Read(payload []byte) (int, error) {
	packet := buf.With(payload)
	if _, err := p.ReadPacket(packet); err != nil {
		return 0, err
	}
	return packet.Len(), nil
}

func (p *packetStream) Write(payload []byte) (int, error) {
	if err := p.WritePacket(buf.As(payload), p.destination); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (p *packetStream) RemoteAddr() net.Addr { return p.destination.UDPAddr() }
