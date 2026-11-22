package vpn

import (
	"errors"
	"net/netip"

	"github.com/ehzyil/connect-hub/internal/workeripc"
	"github.com/miekg/dns"
)

func validateDNSAliases(prefix string, response *dns.Msg, aliases []workeripc.DNSAlias) error {
	invalid := errors.New("VPN 核心返回了无效的域名地址映射")
	if prefix == "" {
		if len(aliases) > 0 {
			return invalid
		}
		return nil
	}
	p, err := netip.ParsePrefix(prefix)
	if err != nil || p != p.Masked() || p.Bits() < 20 || p.Bits() > 24 || !netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(p.Addr()) || len(aliases) > 32 {
		return invalid
	}
	byIP := make(map[string]workeripc.DNSAlias)
	for _, alias := range aliases {
		a, e1 := netip.ParseAddr(alias.Address)
		o, e2 := netip.ParseAddr(alias.Original)
		if e1 != nil || e2 != nil || !p.Contains(a) || !o.Is4() || !o.IsGlobalUnicast() || o.IsLoopback() || o.IsLinkLocalUnicast() || p.Contains(o) || alias.TTL == 0 || alias.TTL > 60 {
			return invalid
		}
		if old, ok := byIP[alias.Address]; ok && old != alias {
			return invalid
		}
		byIP[alias.Address] = alias
	}
	seen := map[string]bool{}
	for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, rr := range section {
			if a, ok := rr.(*dns.A); ok {
				alias, exists := byIP[a.A.String()]
				if !exists || a.Hdr.Ttl > alias.TTL || a.Hdr.Ttl > 60 {
					return invalid
				}
				seen[a.A.String()] = true
			}
		}
	}
	if len(seen) != len(byIP) {
		return invalid
	}
	return nil
}
