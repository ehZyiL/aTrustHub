package localapps

import (
	"context"

	"github.com/qy/easyconnect/internal/wincapture"
)

type mappedDNS struct {
	session *wincapture.Session
	release func()
	config  CaptureConfig
}

func prepareMappedDNS(ctx context.Context, address string, config CaptureConfig) (aliasBinding, error) {
	session, release, err := wincapture.Acquire(ctx, config.Key, wincapture.Config{Networks: config.Networks, Gateway: config.Gateway, DNSAddress: address, Domains: config.Domains, ReservedPools: config.ReservedPools, AliasNetworks: config.AliasNetworks})
	if err != nil {
		return nil, err
	}
	return &mappedDNS{session: session, release: release, config: config}, nil
}

func (m *mappedDNS) Done() <-chan struct{} { return m.session.Done() }
func (m *mappedDNS) Close() error          { m.release(); return nil }

func (m *mappedDNS) Exchange(ctx context.Context, packet []byte) ([]byte, error) {
	return exchangeMappedDNS(ctx, m.session, m.config, packet)
}
