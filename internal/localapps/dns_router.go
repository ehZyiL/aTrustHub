package localapps

import (
	"context"
	"errors"
)

// The OS has one DNS namespace. Select its gateway once using the production
// resource router, then use exactly that gateway's installed mapping publisher.
func (p *dnsPool) exchangeSelected(ctx context.Context, selectDNS func([]byte) (string, func() bool, error), packet []byte) ([]byte, error) {
	key, current, err := selectDNS(packet)
	if err != nil {
		return nil, err
	}
	if current == nil || !current() {
		return nil, errors.New("DNS 归属已变化")
	}
	p.mu.Lock()
	entry := p.entries[key]
	ready := !p.closed && entry != nil && entry.alias != nil
	p.mu.Unlock()
	if !ready || entry.active != nil && !entry.active() {
		return nil, errors.New("所选网关尚未启用映射接管")
	}
	answer, err := entry.alias.Exchange(ctx, packet)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	ready = !p.closed && p.entries[key] == entry
	p.mu.Unlock()
	if !ready || !current() || entry.active != nil && !entry.active() {
		return nil, errors.New("DNS 查询期间会话或归属已变化")
	}
	return answer, nil
}
