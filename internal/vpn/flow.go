package vpn

import (
	"context"
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
	mu                      sync.Mutex
	sequence                uint64
	pending                 map[string]chan workeripc.FlowResult
	slots                   chan struct{}
}

func newFlowDials(address, user, password string) *flowDials {
	return &flowDials{address: address, user: user, password: password,
		pending: make(map[string]chan workeripc.FlowResult), slots: make(chan struct{}, workeripc.MaxFlowRequests)}
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
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.pending, id); f.mu.Unlock() }()
	d, err := hubproxy.NewSOCKSDialer(f.address, &proxy.Auth{User: f.user + "/" + id, Password: f.password})
	if err != nil {
		return nil, err
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	result := workeripc.ConnectionResult(conn, err)
	result.Target = addr
	// The worker emits before the SOCKS reply. A short grace period only covers
	// scheduling between the independent pipe and socket readers. Observability
	// must not turn a healthy connection into a failure if a report is missing.
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case result = <-ch:
	case <-ctx.Done():
	case <-s.stopping:
	case <-s.done:
	case <-timer.C:
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
	return &flowConn{Conn: conn, result: result}, nil
}

type flowConn struct {
	net.Conn
	result workeripc.FlowResult
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
