package localapps

import (
	"context"

	"github.com/ehzyil/connect-hub/internal/wincapture"
)

type mappedDNS struct {
	session *wincapture.Session
	release func()
	config  CaptureConfig
}

func prepareMappedDNS(ctx context.Context, address string, config CaptureConfig) (aliasBinding, error) {
	settings := windowsSessionConfig(config)
	settings.DNSAddress, settings.Domains = address, config.Domains
	settings.SharedDNS = config.sharedDNSAddress != ""
	session, release, err := wincapture.Acquire(ctx, config.Key, settings)
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
