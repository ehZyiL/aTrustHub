// Package packetstack connects an IPv4 TUN device to the shared packet stack.
package packetstack

// This adapter follows sing-tun's stack_gvisor.go forwarding model, using the
// gVisor API already selected by the reference repositories. The old sing-tun
// build-tagged adapter expects PacketBufferPtr and an obsolete UDP callback.
// TCP/IP, retransmission and packet queues remain upstream implementations.

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	tun "github.com/mythologyli/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

const MTU = 1400

// Device exchanges complete IPv4 packets. ReadPacket returns an owned buffer.
// The caller closes the underlying device before closing the stack to unblock reads.
type Device interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}

type Stack struct {
	ctx     context.Context
	cancel  context.CancelFunc
	device  Device
	handler tun.Handler
	stack   *stack.Stack
	link    *channel.Endpoint
	wg      sync.WaitGroup
	once    sync.Once
}

func New(ctx context.Context, device Device, handler tun.Handler) *Stack {
	life, cancel := context.WithCancel(ctx)
	return &Stack{ctx: life, cancel: cancel, device: device, handler: handler}
}

func (s *Stack) Start() error {
	s.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	s.link = channel.New(256, MTU, "")
	if err := s.stack.CreateNIC(1, s.link); err != nil {
		s.stack.Close()
		s.link.Close()
		return errors.New(err.String())
	}
	s.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 32768,
		Max:     262144,
	}
	s.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt)
	sndOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: 32768,
		Max:     262144,
	}
	s.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt)
	if err := s.stack.SetSpoofing(1, true); err != nil {
		s.stack.Close()
		s.link.Close()
		return errors.New(err.String())
	}
	if err := s.stack.SetPromiscuousMode(1, true); err != nil {
		s.stack.Close()
		s.link.Close()
		return errors.New(err.String())
	}
	tcpForwarder := tcp.NewForwarder(s.stack, 0, 512, func(request *tcp.ForwarderRequest) {
		var queue waiter.Queue
		endpoint, err := request.CreateEndpoint(&queue)
		if err != nil {
			request.Complete(true)
			return
		}
		request.Complete(false)
		endpoint.SocketOptions().SetKeepAlive(true)
		conn := gonet.NewTCPConn(&queue, endpoint)
		go func() {
			defer conn.Close()
			metadata := M.Metadata{Source: M.SocksaddrFromNet(conn.RemoteAddr()), Destination: M.SocksaddrFromNet(conn.LocalAddr())}
			if err := s.handler.NewConnection(s.ctx, conn, metadata); err != nil {
				endpoint.Abort()
			}
		}()
	})
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s.stack, func(request *udp.ForwarderRequest) bool {
		defer request.Packet().DecRef()
		var queue waiter.Queue
		endpoint, err := request.CreateEndpoint(&queue)
		if err != nil {
			return false
		}
		conn := gonet.NewUDPConn(&queue, endpoint)
		go func() {
			defer conn.Close()
			metadata := M.Metadata{Source: M.SocksaddrFromNet(conn.RemoteAddr()), Destination: M.SocksaddrFromNet(conn.LocalAddr())}
			packet := bufio.NewPacketConn(&boundPacketConn{UDPConn: conn})
			if err := s.handler.NewPacketConnection(s.ctx, packet, metadata); err != nil {
				endpoint.Abort()
			}
		}()
		return true
	})
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	s.wg.Add(2)
	go s.readLoop()
	go s.writeLoop()
	return nil
}

type boundPacketConn struct{ *gonet.UDPConn }

// A forwarded gVisor UDP endpoint is connected to the originating client;
// the Handler's destination identifies the remote server, not that client.
func (c *boundPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

func (s *Stack) readLoop() {
	defer s.wg.Done()
	for {
		data, err := s.device.ReadPacket()
		if err != nil {
			if s.ctx.Err() == nil {
				s.handler.NewError(s.ctx, err)
			}
			s.cancel()
			return
		}
		if len(data) < header.IPv4MinimumSize || data[0]>>4 != 4 {
			continue
		}
		// Only pass TCP and UDP to the handlers. A local ICMP echo would make an
		// unreachable VPN target appear healthy.
		if protocol := data[9]; protocol != uint8(tcp.ProtocolNumber) && protocol != uint8(udp.ProtocolNumber) {
			continue
		}
		payload := buffer.MakeWithData(data)
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload, IsForwardedPacket: true})
		s.link.InjectInbound(ipv4.ProtocolNumber, packet)
		packet.DecRef()
	}
}

func (s *Stack) writeLoop() {
	defer s.wg.Done()
	for {
		packet := s.link.ReadContext(s.ctx)
		if packet == nil {
			return
		}
		view := packet.ToView()
		err := s.device.WritePacket(view.AsSlice())
		view.Release()
		packet.DecRef()
		if err != nil {
			if s.ctx.Err() == nil {
				s.handler.NewError(s.ctx, err)
			}
			s.cancel()
			return
		}
	}
}

func (s *Stack) Close() error {
	s.once.Do(func() {
		s.cancel()
		if s.stack != nil {
			s.stack.Close()
			for _, endpoint := range s.stack.CleanupEndpoints() {
				endpoint.Abort()
			}
		}
		if s.link != nil {
			s.link.Close()
		}
		s.wg.Wait()
	})
	return nil
}
