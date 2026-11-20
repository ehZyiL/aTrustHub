package vpn

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	hubproxy "github.com/qy/easyconnect/internal/proxy"
	"github.com/qy/easyconnect/internal/workeripc"
	"golang.org/x/net/proxy"
)

// flowDials belongs to one worker generation. IDs are never reused in that
// generation, even when a dial times out before the result arrives.
type flowDials struct {
	address, user, password string
	vpnAddress              string
	prepare                 bool
	strictUDP               bool
	udpSlots                chan struct{}
	mu                      sync.Mutex
	sequence                uint64
	pending                 map[string]chan workeripc.FlowResult
	ready                   map[string]chan workeripc.Message
	slots                   chan struct{}
}

func newFlowDials(address, user, password string) *flowDials {
	return &flowDials{address: address, user: user, password: password,
		pending: make(map[string]chan workeripc.FlowResult), ready: make(map[string]chan workeripc.Message), slots: make(chan struct{}, workeripc.MaxFlowRequests)}
}

func (f *flowDials) deliverReady(m workeripc.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ch := f.ready[m.RequestID]; ch != nil {
		select {
		case ch <- m:
		default:
		}
	}
}

func (f *flowDials) deliver(m workeripc.Message) bool {
	if len(m.RequestID) == 0 || len(m.RequestID) > 20 || m.Flow == nil || !workeripc.ValidFlowResult(*m.Flow) {
		return false
	}
	f.mu.Lock()
	if ch := f.pending[m.RequestID]; ch != nil {
		select {
		case ch <- *m.Flow:
		default:
		}
	}
	f.mu.Unlock()
	return true
}

func (s *processSession) dialFlow(ctx context.Context, addr string) (net.Conn, error) {
	return s.dialFlowAddress(ctx, addr, s.flows.Load().address)
}

func (s *processSession) dialFlowAddress(ctx context.Context, addr, address string) (net.Conn, error) {
	return s.dialFlowTransport(ctx, addr, address, false)
}

func (s *processSession) dialFlowTransport(ctx context.Context, addr, address string, udp bool) (net.Conn, error) {
	f := s.flows.Load()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	select {
	case f.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.stopping:
		return nil, net.ErrClosed
	case <-s.done:
		return nil, s.Err()
	}
	defer func() { <-f.slots }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.sequence++
	id := strconv.FormatUint(f.sequence, 10)
	ch := make(chan workeripc.FlowResult, 1)
	f.pending[id] = ch
	ready := make(chan workeripc.Message, 1)
	f.ready[id] = ready
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.pending, id); delete(f.ready, id); f.mu.Unlock() }()
	completed := false
	defer func() {
		if !completed {
			select {
			case s.outgoing <- workerWrite{
				ctx:     context.Background(),
				message: workeripc.Message{Type: "flow_cancel", RequestID: id},
				result:  make(chan error, 1),
			}:
			default:
			}
		}
	}()
	if f.prepare {
		deadline, _ := ctx.Deadline()
		if err := s.send(ctx, workeripc.Message{Type: "flow_prepare", RequestID: id, Deadline: deadline.UnixMilli()}); err != nil {
			return nil, err
		}
		select {
		case message := <-ready:
			if message.Error != "" {
				return nil, errors.New("VPN 核心无法准备连接：已过期或繁忙")
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.stopping:
			return nil, net.ErrClosed
		case <-s.done:
			return nil, s.Err()
		}
	}
	auth := &proxy.Auth{User: f.user + "/" + id, Password: f.password}
	var conn net.Conn
	var err error
	if udp {
		conn, err = dialWorkerUDP(ctx, address, addr, auth, f.udpSlots)
	} else {
		d, dialErr := hubproxy.NewSOCKSDialer(address, auth)
		if dialErr != nil {
			return nil, dialErr
		}
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	result := workeripc.ConnectionResult(conn, err)
	result.Target = addr
	// The worker emits before the SOCKS reply. A short grace period only covers
	// scheduling between the independent pipe and socket readers. Observability
	// must not turn a healthy connection into a failure if a report is missing.
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	reported := false
	select {
	case result = <-ch:
		reported = true
	case <-ctx.Done():
	case <-s.stopping:
	case <-s.done:
	case <-timer.C:
	}
	if udp && ctx.Err() != nil {
		err = ctx.Err()
		if conn != nil {
			_ = conn.Close()
			conn = nil
		}
	}
	if err == nil {
		select {
		case <-s.stopping:
			err = net.ErrClosed
		case <-s.done:
			err = s.Err()
		default:
			err = ctx.Err()
		}
		if err == nil && udp && (!reported || result.Route != "vpn" || result.Failure != "") {
			err = errors.New("核心未确认 UDP 目标的 VPN 授权")
		}
		if err != nil {
			_ = conn.Close()
			conn = nil
		}
	}
	if err != nil {
		if result.Failure == "" {
			result.Failure = "connect"
		}
		return nil, &flowDialError{error: err, result: result}
	}
	// A contradictory report is never promoted to a claimed VPN path.
	if result.Failure != "" {
		result = workeripc.FlowResult{Target: addr, Route: "unknown"}
	}
	completed = true
	return &flowConn{Conn: conn, result: result}, nil
}

type flowConn struct {
	net.Conn
	result workeripc.FlowResult
}

func (c *flowConn) transportDone() <-chan struct{} {
	if u, ok := c.Conn.(*workerUDPConn); ok {
		return u.done
	}
	return nil
}

func (c *flowConn) FlowResult() workeripc.FlowResult { return c.result }
func (c *flowConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type flowDialError struct {
	error
	result workeripc.FlowResult
}

func (e *flowDialError) FlowResult() workeripc.FlowResult { return e.result }
func (e *flowDialError) Unwrap() error                    { return e.error }
