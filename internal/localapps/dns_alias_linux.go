package localapps

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/capture"
	"github.com/qy/easyconnect/internal/resolved"
)

type mappedDNS struct {
	lease  *capture.AliasLease
	config CaptureConfig
}

func prepareMappedDNS(ctx context.Context, address string, config CaptureConfig) (aliasBinding, error) {
	lease, err := capture.PrepareAliases(ctx, resolved.Config{Address: address, Domains: config.Domains}, config.Networks)
	if err != nil {
		return nil, err
	}
	return &mappedDNS{lease: lease, config: config}, nil
}
func (m *mappedDNS) Done() <-chan struct{} { return m.lease.Done() }
func (m *mappedDNS) Close() error          { return m.lease.Close() }
func (m *mappedDNS) Exchange(ctx context.Context, packet []byte) ([]byte, error) {
	started := time.Now()
	reply, err := m.config.MappedDNS(ctx, packet, m.lease.Prefix)
	if err != nil {
		return nil, err
	}
	if err = m.lease.Publish(ctx, reply.DNSAliases); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// Count IPC and rule installation against the advertised lifetime. The
	// consumer must not cache a result beyond the worker's authorization lease.
	response := new(dns.Msg)
	if err = response.Unpack(reply.DNS); err != nil {
		return nil, err
	}
	spent := time.Since(started)
	elapsed := uint32((spent + time.Second - 1) / time.Second)
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			if _, opt := rr.(*dns.OPT); opt {
				continue
			}
			if rr.Header().Ttl > elapsed {
				rr.Header().Ttl -= elapsed
			} else {
				rr.Header().Ttl = 0
			}
		}
	}
	for _, alias := range reply.DNSAliases {
		if spent >= time.Duration(alias.TTL)*time.Second {
			return nil, errors.New("DNS 规则安装超过应答有效期，请重试")
		}
	}
	return response.Pack()
}
