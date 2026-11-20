package localapps

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/wincapture"
)

type mappedDNS struct {
	session *wincapture.Session
	release func()
	config  CaptureConfig
}

func prepareMappedDNS(ctx context.Context, address string, config CaptureConfig) (aliasBinding, error) {
	session, release, err := wincapture.Acquire(ctx, config.Key, wincapture.Config{Networks: config.Networks, Gateway: config.Gateway, DNSAddress: address, Domains: config.Domains})
	if err != nil {
		return nil, err
	}
	return &mappedDNS{session: session, release: release, config: config}, nil
}
func (m *mappedDNS) Done() <-chan struct{} { return m.session.Done() }
func (m *mappedDNS) Close() error          { m.release(); return nil }
func (m *mappedDNS) Exchange(ctx context.Context, packet []byte) ([]byte, error) {
	started := time.Now()
	reply, err := m.config.MappedDNS(ctx, packet, m.session.Prefix())
	if err != nil {
		return nil, err
	}
	if err = m.session.Publish(ctx, reply.DNSAliases); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
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
