package localapps

import (
	"context"

	"github.com/qy/easyconnect/internal/capture"
	"github.com/qy/easyconnect/internal/resolved"
	"github.com/qy/easyconnect/internal/workeripc"
)

type mappedDNS struct {
	lease  *capture.AliasLease
	config CaptureConfig
}

type linuxAliasPublisher struct {
	lease *capture.AliasLease
}

func (l linuxAliasPublisher) Prefix() string { return l.lease.Prefix }
func (l linuxAliasPublisher) Publish(ctx context.Context, aliases []workeripc.DNSAlias) error {
	return l.lease.Publish(ctx, aliases)
}

func prepareMappedDNS(ctx context.Context, address string, config CaptureConfig) (aliasBinding, error) {
	resources := append(append(config.Networks[:0:0], config.Networks...), config.AliasNetworks...)
	var required string
	if config.MappingPrefix != nil {
		var err error
		required, err = config.MappingPrefix()
		if err != nil {
			return nil, err
		}
	}
	lease, err := capture.PrepareAliasesForPool(ctx, resolved.Config{Address: address, Domains: config.Domains}, resources, required, config.ReservedPools)
	if err != nil {
		return nil, err
	}
	return &mappedDNS{lease: lease, config: config}, nil
}

func (m *mappedDNS) Done() <-chan struct{}  { return m.lease.Done() }
func (m *mappedDNS) Close() error           { return m.lease.Close() }
func (m *mappedDNS) Ref() *capture.AliasRef { return m.lease.Ref() }
func (m *mappedDNS) Prefix() string         { return m.lease.Prefix }

func (m *mappedDNS) Exchange(ctx context.Context, packet []byte) ([]byte, error) {
	return exchangeMappedDNS(ctx, linuxAliasPublisher{m.lease}, m.config, packet)
}
