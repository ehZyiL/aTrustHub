package vpn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/workeripc"
	"github.com/things-go/go-socks5/statute"
	"golang.org/x/net/proxy"
)

// dialWorkerUDP uses only the worker's authenticated IPv4 loopback listener.
// The association is tied to both sockets. The dial timeout ends at ready.
func dialWorkerUDP(ctx context.Context, address, target string, auth *proxy.Auth, slots chan struct{}) (net.Conn, error) {
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	peer, err := netip.ParseAddrPort(address)
	if err != nil || peer.Addr() != loopback || peer.Port() == 0 {
		return nil, errors.New("核心 UDP 控制地址无效")
	}
	if auth == nil || len(auth.User) == 0 || len(auth.User) > 255 || len(auth.Password) == 0 || len(auth.Password) > 255 {
		return nil, errors.New("核心 UDP 凭据格式无效")
	}
	marker, err := statute.NewDatagram(target, []byte{0})
	if err != nil || marker.DstAddr.AddrType == statute.ATYPIPv6 || marker.DstAddr.Port < 1 || marker.DstAddr.Port > 65535 {
		return nil, errors.New("核心 UDP 目标无效")
	}
	select {
	case slots <- struct{}{}:
	default:
		return nil, errors.New("核心 UDP 会话已满")
	}
	open := false
	defer func() {
		if !open {
			<-slots
		}
	}()
	packet, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loopback, 0)))
	if err != nil {
		return nil, err
	}
	defer func() {
		if !open {
			_ = packet.Close()
		}
	}()
	control, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !open {
			_ = control.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = control.SetDeadline(deadline)
	}
	if err := udpAuth(control, auth); err != nil {
		return nil, err
	}
	port := uint16(packet.LocalAddr().(*net.UDPAddr).Port)
	request := []byte{5, statute.CommandAssociate, 0, statute.ATYPIPv4, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], port)
	if _, err := control.Write(request); err != nil {
		return nil, err
	}
	reply, err := statute.ParseReply(control)
	if err != nil || reply.Reserved != 0 || reply.Response != statute.RepSuccess || reply.BndAddr.AddrType != statute.ATYPIPv4 || !reply.BndAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) || reply.BndAddr.Port == 0 {
		return nil, errors.New("核心未建立可信的 UDP 中继")
	}
	relay := netip.AddrPortFrom(loopback, uint16(reply.BndAddr.Port))
	if relay.Port() == port {
		return nil, errors.New("核心返回了本地 UDP 来源地址")
	}
	if _, err = packet.WriteToUDPAddrPort(marker.Bytes(), relay); err != nil {
		return nil, err
	}
	var ready [1]byte
	if _, err = io.ReadFull(control, ready[:]); err != nil {
		return nil, err
	}
	if ready[0] != 0 || !stop() || ctx.Err() != nil {
		return nil, errors.New("核心未确认 UDP 目标")
	}
	if err := control.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	c := &workerUDPConn{packet: packet, control: control, relay: relay, target: marker.DstAddr, slots: slots, done: make(chan struct{})}
	open = true
	go func() {
		var b [1]byte
		_, _ = control.Read(b[:])
		_ = c.Close()
	}()
	return c, nil
}

func udpAuth(conn net.Conn, auth *proxy.Auth) error {
	var reply [2]byte
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 2} {
		return errors.New("核心 UDP 代理未使用凭据认证")
	}
	request := make([]byte, 0, 3+len(auth.User)+len(auth.Password))
	request = append(request, 1, byte(len(auth.User)))
	request = append(request, auth.User...)
	request = append(request, byte(len(auth.Password)))
	request = append(request, auth.Password...)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{1, 0} {
		return errors.New("核心 UDP 代理认证失败")
	}
	return nil
}

type workerUDPConn struct {
	packet  *net.UDPConn
	control net.Conn
	relay   netip.AddrPort
	target  statute.AddrSpec
	slots   chan struct{}
	done    chan struct{}
	once    sync.Once
	readMu  sync.Mutex
	readBuf [65535]byte
}

func (c *workerUDPConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n, from, err := c.packet.ReadFromUDPAddrPort(c.readBuf[:])
		if err != nil {
			return 0, err
		}
		if from != c.relay || n < 4 || c.readBuf[0] != 0 || c.readBuf[1] != 0 || c.readBuf[2] != 0 {
			continue
		}
		address, data, err := workeripc.DecodeUDPFrame(c.readBuf[:n])
		if err != nil || address != c.target.String() {
			continue
		}
		if len(data) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, data), nil
	}
}

func (c *workerUDPConn) Write(b []byte) (int, error) {
	if len(b) > workeripc.MaxUDPPayload {
		return 0, errors.New("UDP 数据报过大")
	}
	d := statute.Datagram{DstAddr: c.target, Data: b}
	if _, err := c.packet.WriteToUDPAddrPort(d.Bytes(), c.relay); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *workerUDPConn) Close() error {
	c.once.Do(func() { _ = c.packet.Close(); _ = c.control.Close(); <-c.slots; close(c.done) })
	return nil
}

func (c *workerUDPConn) LocalAddr() net.Addr                { return c.packet.LocalAddr() }
func (c *workerUDPConn) RemoteAddr() net.Addr               { return net.UDPAddrFromAddrPort(c.relay) }
func (c *workerUDPConn) SetDeadline(t time.Time) error      { return c.packet.SetDeadline(t) }
func (c *workerUDPConn) SetReadDeadline(t time.Time) error  { return c.packet.SetReadDeadline(t) }
func (c *workerUDPConn) SetWriteDeadline(t time.Time) error { return c.packet.SetWriteDeadline(t) }

func supportsStrictUDP(s Session) bool {
	c, ok := s.(StrictUDPSession)
	return ok && c.SupportsStrictUDP()
}

// A UDP association never migrates to a reconnected gateway or another exit.
type scopedUDPConn struct {
	net.Conn
	current func() bool
	done    chan struct{}
	once    sync.Once
}

func newScopedUDPConn(conn net.Conn, sessionDone <-chan struct{}, current func() bool) net.Conn {
	c := &scopedUDPConn{Conn: conn, current: current, done: make(chan struct{})}
	var transportDone <-chan struct{}
	if transport, ok := conn.(*flowConn); ok {
		transportDone = transport.transportDone()
	}
	go func() {
		select {
		case <-sessionDone:
			_ = c.Close()
		case <-transportDone:
			_ = c.Close()
		case <-c.done:
		}
	}()
	return c
}

func (c *scopedUDPConn) Close() error {
	c.once.Do(func() { close(c.done); _ = c.Conn.Close() })
	return nil
}

func (c *scopedUDPConn) Read(b []byte) (int, error) {
	if !c.current() {
		_ = c.Close()
		return 0, net.ErrClosed
	}
	n, err := c.Conn.Read(b)
	if !c.current() {
		_ = c.Close()
		return 0, net.ErrClosed
	}
	return n, err
}

func (c *scopedUDPConn) Write(b []byte) (int, error) {
	if !c.current() {
		_ = c.Close()
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}
