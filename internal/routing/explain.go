package routing

import (
	"fmt"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

type Match struct {
	GatewayID, Source   string
	Current, Authorized bool
}

func matches(g Gateway, host string, port int, network string) []Match {
	var out []Match
	add := func(s *workeripc.ResourceSnapshot, current bool) {
		if s == nil {
			return
		}
		for _, r := range s.IPRules {
			if ipMatch(r, host) {
				out = append(out, Match{g.ID, fmt.Sprintf("IP %s–%s %s:%d–%d", r.Min, r.Max, r.Protocol, r.PortMin, r.PortMax), current, current && authorized(r.Protocol, r.PortMin, r.PortMax, port, network)})
			}
		}
		for _, r := range s.DomainRules {
			if DomainSpecificity(r.Domain, host) > 0 {
				out = append(out, Match{g.ID, fmt.Sprintf("域名 %s %s:%d–%d", r.Domain, r.Protocol, r.PortMin, r.PortMax), current, current && authorized(r.Protocol, r.PortMin, r.PortMax, port, network)})
			}
		}
		for _, r := range s.StaticDNS {
			if name, e := NormalizeHost(r.Name); e == nil && name == host {
				out = append(out, Match{g.ID, "静态 DNS " + r.Name, current, false})
			}
		}
		for _, r := range s.InternalDomains {
			if DomainSpecificity(r, host) > 0 {
				out = append(out, Match{g.ID, "DNS 后缀 " + r, current, false})
			}
		}
	}
	add(g.Current, true)
	if len(out) == 0 {
		add(g.Known, false)
	}
	return out
}
