package adapter

import (
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// workerResources converts a peer snapshot into the local routing shape. The
// caller must have validated it first; no app id is invented, because an
// imported share has no per-app attribution on this side.
func workerResources(in *relay.ResourceSnapshot) *workeripc.ResourceSnapshot {
	if in == nil {
		return nil
	}
	out := &workeripc.ResourceSnapshot{
		DNSServer:       in.DNSServer,
		InternalDomains: append([]string(nil), in.InternalDomains...),
		Tunnel:          "ipv4-l3",
	}
	out.IPRules = make([]workeripc.IPRule, 0, len(in.IPRules))
	for _, r := range in.IPRules {
		out.IPRules = append(out.IPRules, workeripc.IPRule{Min: r.Min, Max: r.Max, PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol})
	}
	out.DomainRules = make([]workeripc.DomainRule, 0, len(in.DomainRules))
	for _, r := range in.DomainRules {
		out.DomainRules = append(out.DomainRules, workeripc.DomainRule{Domain: r.Domain, PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol})
	}
	out.StaticDNS = make([]workeripc.DNSRecord, 0, len(in.StaticDNS))
	for _, r := range in.StaticDNS {
		out.StaticDNS = append(out.StaticDNS, workeripc.DNSRecord{Name: r.Name, Addresses: append([]string(nil), r.Addresses...)})
	}
	return out
}
