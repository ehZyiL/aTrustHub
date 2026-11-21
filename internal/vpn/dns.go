package vpn

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

// DNSExchanger is optional; aTrust sessions retain their existing behavior.
// It only accepts internal DNS questions scoped to this EasyConnect session.
type DNSExchanger interface {
	ExchangeDNS(context.Context, []byte) ([]byte, error)
}

// ExchangeDNS binds one diagnostic to the current session and discards a late
// response if the endpoint was disconnected or replaced in the meantime.
func (m *Manager) ExchangeDNS(ctx context.Context, id string, packet []byte) ([]byte, error) {
	return m.exchangeDNS(ctx, id, packet, false)
}

func (m *Manager) ExchangeCaptureDNS(ctx context.Context, id string, packet []byte) ([]byte, error) {
	return m.exchangeDNS(ctx, id, packet, true)
}

func (m *Manager) exchangeDNS(ctx context.Context, id string, packet []byte, capture bool) ([]byte, error) {
	m.mu.RLock()
	ep := m.points[id]
	if ep == nil || ep.state != StateOnline || ep.sess == nil {
		m.mu.RUnlock()
		return nil, errors.New("请先登录所选 VPN 接入点")
	}
	gen, sess := ep.gen, ep.sess
	m.mu.RUnlock()
	var exchange func(context.Context, []byte) ([]byte, error)
	if capture {
		if s, ok := sess.(interface {
			ExchangeCaptureDNS(context.Context, []byte) ([]byte, error)
		}); ok {
			exchange = s.ExchangeCaptureDNS
		}
	} else if s, ok := sess.(DNSExchanger); ok {
		exchange = s.ExchangeDNS
	}
	if exchange == nil {
		return nil, errors.New("该连接核心不支持 DNS 诊断")
	}
	result, err := exchange(ctx, packet)
	m.mu.RLock()
	current := m.points[id]
	valid := current == ep && current.gen == gen && current.state == StateOnline && !m.closed
	m.mu.RUnlock()
	if !valid {
		return nil, errors.New("VPN 会话已变化，请重新查询")
	}
	return result, err
}

func (m *Manager) DNSResources(id string) *workeripc.ResourceSnapshot {
	m.mu.RLock()
	ep := m.points[id]
	if ep == nil || ep.state != StateOnline || ep.sess == nil {
		m.mu.RUnlock()
		return nil
	}
	sess := ep.sess
	m.mu.RUnlock()
	return sess.Info().Resources
}

func (s *processSession) ExchangeDNS(ctx context.Context, packet []byte) ([]byte, error) {
	return s.exchangeDNS(ctx, packet, false)
}

func (s *processSession) ExchangeCaptureDNS(ctx context.Context, packet []byte) ([]byte, error) {
	return s.exchangeDNS(ctx, packet, true)
}

func (s *processSession) exchangeDNS(ctx context.Context, packet []byte, capture bool) ([]byte, error) {
	result, err := s.exchangeDNSReply(ctx, packet, capture, "")
	return result.DNS, err
}

// ExchangeMappedDNS is reserved for a platform which has already allocated a
// conflict-checked synthetic range. The returned packet must not be published
// until every returned alias is installed for unselected applications.
func (s *processSession) ExchangeMappedDNS(ctx context.Context, packet []byte, prefix string) (workeripc.Message, error) {
	return s.exchangeDNSReply(ctx, packet, true, prefix)
}

func (s *processSession) exchangeDNSReply(ctx context.Context, packet []byte, capture bool, prefix string) (workeripc.Message, error) {
	if len(packet) < 12 || len(packet) > workeripc.MaxDNSMessage {
		return workeripc.Message{}, errors.New("DNS 请求长度无效")
	}
	q := new(dns.Msg)
	if q.Unpack(packet) != nil || q.Response || q.Opcode != dns.OpcodeQuery || len(q.Question) != 1 {
		return workeripc.Message{}, errors.New("DNS 请求格式无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	select {
	case s.dnsSlots <- struct{}{}:
	case <-ctx.Done():
		return workeripc.Message{}, ctx.Err()
	case <-s.stopping:
		return workeripc.Message{}, net.ErrClosed
	case <-s.done:
		return workeripc.Message{}, s.Err()
	}
	defer func() { <-s.dnsSlots }()
	if err := ctx.Err(); err != nil {
		return workeripc.Message{}, err
	}
	s.dnsMu.Lock()
	s.dnsSequence++
	id := strconv.FormatUint(s.dnsSequence, 10)
	ch := make(chan workeripc.Message, 1)
	s.dnsPending[id] = ch
	s.dnsMu.Unlock()
	defer func() { s.dnsMu.Lock(); delete(s.dnsPending, id); s.dnsMu.Unlock() }()
	// Cancellation is best effort on the control pipe, and is never allowed to
	// delay the caller. The worker also bounds every query to six seconds.
	defer func() {
		if ctx.Err() != nil {
			select {
			case s.outgoing <- workerWrite{ctx: context.Background(), message: workeripc.Message{Type: "dns_cancel", RequestID: id}, result: make(chan error, 1)}:
			default:
			}
		}
	}()
	if err := s.send(ctx, workeripc.Message{Type: "dns_query", RequestID: id, DNS: packet, CaptureDNS: capture, CapturePrefix: prefix}); err != nil {
		return workeripc.Message{}, err
	}
	select {
	case <-ctx.Done():
		return workeripc.Message{}, ctx.Err()
	case <-s.stopping:
		return workeripc.Message{}, net.ErrClosed
	case <-s.done:
		return workeripc.Message{}, s.Err()
	case result := <-ch:
		if result.Error != "" {
			return workeripc.Message{}, errors.New("VPN DNS 查询失败或服务繁忙")
		}
		r := new(dns.Msg)
		if len(result.DNS) > workeripc.MaxDNSMessage || r.Unpack(result.DNS) != nil || !r.Response || r.Id != q.Id || r.Opcode != q.Opcode || len(r.Question) != 1 ||
			!strings.EqualFold(r.Question[0].Name, q.Question[0].Name) || r.Question[0].Qtype != q.Question[0].Qtype || r.Question[0].Qclass != q.Question[0].Qclass {
			return workeripc.Message{}, errors.New("VPN DNS 返回了不匹配的应答")
		}
		if err := validateDNSAliases(prefix, r, result.DNSAliases); err != nil {
			return workeripc.Message{}, err
		}
		return result, nil
	}
}
