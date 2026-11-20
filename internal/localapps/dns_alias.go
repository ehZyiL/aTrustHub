package localapps

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/workeripc"
)

type aliasPublisher interface {
	Prefix() string
	Publish(ctx context.Context, aliases []workeripc.DNSAlias) error
}

func exchangeMappedDNS(ctx context.Context, pub aliasPublisher, config CaptureConfig, packet []byte) ([]byte, error) {
	started := time.Now()
	if config.BeginPublication != nil {
		finish, err := config.BeginPublication(pub.Prefix())
		if err != nil {
			return nil, err
		}
		defer finish()
	}
	reply, err := config.MappedDNS(ctx, packet, pub.Prefix())
	if err != nil {
		return nil, err
	}
	if err = pub.Publish(ctx, reply.DNSAliases); err != nil {
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
	if config.ConfirmAliases != nil {
		if err = config.ConfirmAliases(reply.DNSAliases); err != nil {
			return nil, err
		}
	}
	return response.Pack()
}
