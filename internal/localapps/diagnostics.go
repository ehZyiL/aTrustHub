package localapps

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"time"
)

// ExchangeRunningMappedDNS uses the installed runtime's loopback DNS listener,
// including its normal mapping publication/confirmation path. It never starts
// capture or allocates a second helper/lease for diagnostics.
func (m *Manager) ExchangeRunningMappedDNS(ctx context.Context, key string, packet []byte) ([]byte, error) {
	p := &m.dns
	p.mu.Lock()
	e := p.entries[key]
	if p.closed || e == nil || e.alias == nil {
		p.mu.Unlock()
		return nil, errors.New("未启用该会话的接管，无法检查运行中的映射链路")
	}
	address := e.server.Addr()
	active := e.active
	p.mu.Unlock()
	if active != nil && !active() {
		return nil, errors.New("接管会话已结束")
	}
	q := new(dns.Msg)
	if q.Unpack(packet) != nil {
		return nil, errors.New("无效 DNS 请求")
	}
	reply, _, err := (&dns.Client{Net: "tcp", Timeout: 8 * time.Second}).ExchangeContext(ctx, q, address)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	current := !p.closed && p.entries[key] == e
	p.mu.Unlock()
	if !current || (active != nil && !active()) {
		return nil, errors.New("检查期间接管会话已变化")
	}
	return reply.Pack()
}
