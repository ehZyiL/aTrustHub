package vpn

import (
	"github.com/ehzyil/connect-hub/internal/relay"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// relayResources converts the local worker snapshot into the LAN DTO. It keeps
// only what the share needs: attribution, ports and static DNS. The app id stays
// behind because the host has already applied its own 停用应用 switches.
func relayResources(in *workeripc.ResourceSnapshot) *relay.ResourceSnapshot {
	if in == nil {
		return nil
	}
	out := &relay.ResourceSnapshot{
		DNSServer:       in.DNSServer,
		InternalDomains: append([]string(nil), in.InternalDomains...),
	}
	out.IPRules = make([]relay.IPRule, 0, len(in.IPRules))
	for _, r := range in.IPRules {
		out.IPRules = append(out.IPRules, relay.IPRule{Min: r.Min, Max: r.Max, PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol})
	}
	out.DomainRules = make([]relay.DomainRule, 0, len(in.DomainRules))
	for _, r := range in.DomainRules {
		out.DomainRules = append(out.DomainRules, relay.DomainRule{Domain: r.Domain, PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol})
	}
	out.StaticDNS = make([]relay.DNSRecord, 0, len(in.StaticDNS))
	for _, r := range in.StaticDNS {
		out.StaticDNS = append(out.StaticDNS, relay.DNSRecord{Name: r.Name, Addresses: append([]string(nil), r.Addresses...)})
	}
	// A session may list an address where a domain is expected. Such an entry
	// cannot travel as a name, and sharing it verbatim would make every client
	// reject the whole snapshot, so it is dropped here - once, on the host -
	// instead of failing the login of every colleague.
	out.DropUnusableDomains()
	out.Normalize()
	return out
}

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

// shareRevisionOf is the effective TCP revision of a local snapshot.
func shareRevisionOf(in *workeripc.ResourceSnapshot, caps relay.Capabilities) string {
	if in == nil {
		return ""
	}
	return relayResources(in).PublishTCP().Revision(caps)
}
