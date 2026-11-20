package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/routing"
	"github.com/qy/easyconnect/internal/workeripc"
)

func resourceVersion(s *workeripc.ResourceSnapshot) string { return routing.Version(s) }

type routedSession struct {
	candidate
	endpoint *endpoint
	gen      int
	version  string
}

func (m *Manager) routeSnapshot(boundID string) ([]routing.Gateway, map[string]routedSession, model.Settings) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	gateways := make([]routing.Gateway, 0, len(m.order))
	sessions := make(map[string]routedSession)
	for _, id := range m.order {
		ep := m.points[id]
		if ep == nil {
			continue
		}
		_, strict := ep.sess.(StrictSession)
		if s, ok := ep.sess.(*processSession); ok {
			f := s.flows.Load()
			strict = f != nil && f.vpnAddress != "" && f.prepare
		}
		version := ep.resourceVersion
		if version == "" {
			version = resourceVersion(ep.info.Resources)
		}
		gateways = append(gateways, routing.Gateway{ID: id, Name: ep.cfg.Name, Generation: ep.gen, Version: version, Online: !m.closed && ep.state == StateOnline && (ep.sess != nil || ep.tunServed), Excluded: !ep.cfg.InPool, Strict: strict || ep.tunServed, Current: ep.info.Resources, Known: ep.knownResources})
		sessions[id] = routedSession{candidate: candidate{id: id, name: ep.cfg.Name, sess: ep.sess, apps: ep.info.Apps, served: ep.tunServed}, endpoint: ep, gen: ep.gen, version: version}
	}
	return gateways, sessions, m.settings
}

// PreviewRoute has no DNS, network, metrics or allocation side effects.
func (m *Manager) PreviewRoute(request routing.Request) routing.Decision {
	gateways, _, settings := m.routeSnapshot(request.GatewayID)
	return routing.Decide(request, gateways, settings.SharedExits, settings.RoutePolicies...)
}

func (m *Manager) currentRoute(c routedSession, boundID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ep := m.points[c.id]
	return !m.closed && ep != nil && ep == c.endpoint && ep.gen == c.gen && ep.tunServed == c.served && ep.state == StateOnline && (ep.cfg.InPool || boundID == c.id) && (ep.resourceVersion == "" || ep.resourceVersion == c.version)
}

func (m *Manager) dialResource(ctx context.Context, network, addr string) (net.Conn, error) {
	return m.dialRoute(ctx, routing.Request{Network: network, Address: addr, Entry: "统一代理"}, nil)
}

// dialBound retains a launcher's session identity. Public traffic keeps its
// original path; a known resource owned by another gateway is never borrowed.
func (m *Manager) dialBound(ctx context.Context, network, addr, id string, gen int, ep *endpoint, mapped bool, original ...string) (net.Conn, error) {
	r := routing.Request{Network: network, Address: addr, GatewayID: id, AllowUnmanaged: true, Mapped: mapped, Entry: "指定网关入口"}
	if len(original) > 0 {
		r.OriginalAddress = original[0]
	}
	return m.dialRoute(ctx, r, &routedSession{candidate: candidate{id: id}, endpoint: ep, gen: gen})
}

func (m *Manager) dialRoute(ctx context.Context, request routing.Request, required *routedSession) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	network := request.Network
	gateways, sessions, settings := m.routeSnapshot(request.GatewayID)
	if required != nil {
		current, ok := sessions[required.id]
		if !ok || current.gen != required.gen || current.endpoint != required.endpoint || !m.currentRoute(current, request.GatewayID) {
			return nil, net.ErrClosed
		}
	}
	decision := routing.Decide(request, gateways, settings.SharedExits, settings.RoutePolicies...)
	if decision.Action == "blocked" {
		err := errors.New(decision.Reason)
		m.logRoute(request, decision, routedSession{}, 0, 0, err)
		return nil, err
	}
	total, each := settings.TotalTimeoutMS, settings.DialTimeoutMS
	if total <= 0 {
		total = 15000
	}
	if each <= 0 {
		each = 5000
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(total)*time.Millisecond)
	defer cancel()
	if decision.Action == "direct" {
		started := time.Now()
		conn, err := originalRouteDial(ctx, network, decision.Target)
		if required != nil && !m.currentRoute(sessions[required.id], request.GatewayID) {
			if conn != nil {
				conn.Close()
			}
			return nil, net.ErrClosed
		}
		m.logRoute(request, decision, routedSession{}, 1, time.Since(started), err)
		return conn, err
	}
	if settings.Routing == model.RoutingHash {
		routing.Rendezvous(decision.Candidates, network+"/"+decision.Target)
	}
	pool := make([]candidate, 0, len(decision.Candidates))
	for _, c := range decision.Candidates {
		pool = append(pool, sessions[c.ID].candidate)
	}
	tried := make(map[string]bool)
	var lastErr error
	for range pool {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		selected, ok := m.pick(pool, settings.Routing, tried)
		if !ok {
			break
		}
		tried[selected.id] = true
		c := sessions[selected.id]
		if !m.currentRoute(c, decision.GatewayID) {
			lastErr = net.ErrClosed
			continue
		}
		attempt, stop := context.WithTimeout(ctx, time.Duration(each)*time.Millisecond)
		started := time.Now()
		var conn net.Conn
		var err error
		if c.served {
			if ctx.Value(originalDialContextKey{}) != nil {
				stop()
				return nil, errors.New("新系统捕获不能使用旧 TUN 移交会话")
			}
			// Compatibility for the existing aTrust helper which owns this
			// session. New worker-backed system TUN must never use SetTunServed.
			conn, err = directDial(attempt, "tcp", decision.Target)
		} else {
			conn, err = safeStrictDial(attempt, c.sess, "tcp", decision.Target)
		}
		if err == nil {
			err = attempt.Err()
		}
		stop()
		if !m.currentRoute(c, decision.GatewayID) {
			err = net.ErrClosed
		}
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			lastErr = err
			m.recordRouteResult(c, false, time.Since(started))
			m.logRoute(request, decision, c, len(tried), time.Since(started), err)
			continue
		}
		m.recordRouteResult(c, true, time.Since(started))
		m.logRoute(request, decision, c, len(tried), time.Since(started), nil)
		return conn, nil
	}
	if lastErr == nil {
		lastErr = errors.New("所属网关不可用")
	}
	return nil, lastErr
}

func safeStrictDial(ctx context.Context, sess Session, network, addr string) (conn net.Conn, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("严格 VPN 拨号失败：%v", r)
		}
	}()
	strict, ok := sess.(StrictSession)
	if !ok {
		return nil, ErrStrictVPNUnavailable
	}
	conn, err = strict.DialVPN(ctx, network, addr)
	if err == nil && conn == nil {
		err = errors.New("核心未返回连接")
	}
	return
}

func (m *Manager) recordRouteResult(c routedSession, success bool, elapsed time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ep := m.points[c.id]
	if ep == nil || ep != c.endpoint || ep.gen != c.gen || ep.state != StateOnline {
		return
	}
	if !success {
		ep.failed.Add(1)
		return
	}
	old := ep.latencyNS.Load()
	if old == 0 {
		ep.latencyNS.Store(int64(elapsed))
	} else {
		ep.latencyNS.Store(old - old/8 + int64(elapsed)/8)
	}
	ep.lastTraffic = time.Now()
	ep.tunnelFails = 0
	ep.tunnelRebuilds = 0
}
