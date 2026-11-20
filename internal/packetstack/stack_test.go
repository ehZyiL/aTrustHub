package packetstack

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type memoryTun struct {
	ctx    context.Context
	cancel context.CancelFunc
	client *channel.Endpoint
	once   sync.Once
}

func (d *memoryTun) ReadPacket() ([]byte, error) {
	p := d.client.ReadContext(d.ctx)
	if p == nil {
		return nil, io.EOF
	}
	v := p.ToView()
	p.DecRef()
	defer v.Release()
	return append([]byte(nil), v.AsSlice()...), nil
}
func (d *memoryTun) WritePacket(data []byte) error {
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data...))})
	d.client.InjectInbound(ipv4.ProtocolNumber, packet)
	packet.DecRef()
	return nil
}
func (d *memoryTun) Close() error { d.once.Do(d.cancel); return nil }

type echoHandler struct {
	seen     chan M.Metadata
	failures chan error
}

func (h *echoHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	h.seen <- metadata
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Wait for the client's FIN before sending the reply: verifies half-close
	// behavior needed by database/HTTP tools, not just a successful SYN.
	data, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	_, err = conn.Write(append([]byte("reply:"), data...))
	return err
}
func (h *echoHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	h.seen <- metadata
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	b := buf.NewSize(65535)
	if _, err := conn.ReadPacket(b); err != nil {
		b.Release()
		return err
	}
	return conn.WritePacket(b, metadata.Destination)
}
func (h *echoHandler) NewError(_ context.Context, err error) {
	select {
	case h.failures <- err:
	default:
	}
}

func TestPacketStackTCPHalfCloseAndUDP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	link := channel.New(128, MTU, "")
	if err := client.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	source := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	if err := client.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: source, PrefixLen: 24}}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	client.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	life, stop := context.WithCancel(ctx)
	device := &memoryTun{ctx: life, cancel: stop, client: link}
	handler := &echoHandler{seen: make(chan M.Metadata, 2), failures: make(chan error, 2)}
	server := New(ctx, device, handler)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); device.Close(); server.Close(); client.Close(); link.Close() }()
	destination := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{203, 0, 113, 7}), Port: 15432}
	conn, err := gonet.DialContextTCP(ctx, client, destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("database-request")); err != nil {
		t.Fatal(err)
	}
	if err = conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	conn.Close()
	if err != nil || !bytes.Equal(data, []byte("reply:database-request")) {
		t.Fatalf("TCP payload: %q, %v", data, err)
	}
	select {
	case meta := <-handler.seen:
		if meta.Source.Addr.String() != "192.0.2.1" || meta.Destination.String() != "203.0.113.7:15432" {
			t.Fatalf("lost original tuple: %+v", meta)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	destination.Port = 53
	packet, err := gonet.DialUDP(client, nil, &destination, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = packet.Write([]byte("dns-payload")); err != nil {
		t.Fatal(err)
	}
	data = make([]byte, 128)
	n, err := packet.Read(data)
	if err != nil || string(data[:n]) != "dns-payload" {
		t.Fatalf("UDP reply: %q, %v", data[:n], err)
	}
	select {
	case meta := <-handler.seen:
		if meta.Source.Addr.String() != "192.0.2.1" || meta.Destination.String() != "203.0.113.7:53" {
			t.Fatalf("UDP tuple: %+v", meta)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
