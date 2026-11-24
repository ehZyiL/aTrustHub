// Package attribution keeps the attribution history of a managed target.
//
// History answers one question only: "has this target ever been owned by this
// access point?" It is used to stop a target that was once managed from
// silently falling back to the original network. It never authorizes anything;
// authorization always comes from the current resource snapshot.
package attribution

import "github.com/ehzyil/connect-hub/internal/workeripc"

// Clone returns a deep copy. Callers never share a snapshot with the caller
// that produced it.
func Clone(in *workeripc.ResourceSnapshot) *workeripc.ResourceSnapshot {
	if in == nil {
		return nil
	}
	out := *in
	out.IPRules = append([]workeripc.IPRule(nil), in.IPRules...)
	out.DomainRules = append([]workeripc.DomainRule(nil), in.DomainRules...)
	out.InternalDomains = append([]string(nil), in.InternalDomains...)
	out.StaticDNS = append([]workeripc.DNSRecord(nil), in.StaticDNS...)
	for i := range out.StaticDNS {
		out.StaticDNS[i].Addresses = append([]string(nil), in.StaticDNS[i].Addresses...)
	}
	return &out
}

// Merge returns the union of the history already known and the snapshot just
// verified. Entries are never removed: a target that was withdrawn stays owned
// so it cannot become an ordinary direct connection later. Duplicates are
// dropped so repeated snapshots do not grow the cache.
//
// Current (authorization) must always come from the newest verified snapshot,
// never from this result.
func Merge(known, current *workeripc.ResourceSnapshot) *workeripc.ResourceSnapshot {
	if current == nil {
		return known
	}
	if known == nil {
		return Clone(current)
	}
	out := Clone(known)
	ips := make(map[workeripc.IPRule]bool)
	for _, r := range out.IPRules {
		ips[r] = true
	}
	for _, r := range current.IPRules {
		if !ips[r] {
			out.IPRules = append(out.IPRules, r)
			ips[r] = true
		}
	}
	domains := make(map[workeripc.DomainRule]bool)
	for _, r := range out.DomainRules {
		domains[r] = true
	}
	for _, r := range current.DomainRules {
		if !domains[r] {
			out.DomainRules = append(out.DomainRules, r)
			domains[r] = true
		}
	}
	names := make(map[string]bool)
	for _, s := range out.InternalDomains {
		names[s] = true
	}
	for _, s := range current.InternalDomains {
		if !names[s] {
			out.InternalDomains = append(out.InternalDomains, s)
			names[s] = true
		}
	}
	records := make(map[string]int)
	for i, r := range out.StaticDNS {
		records[r.Name] = i
	}
	for _, r := range current.StaticDNS {
		i, ok := records[r.Name]
		if !ok {
			records[r.Name] = len(out.StaticDNS)
			out.StaticDNS = append(out.StaticDNS, workeripc.DNSRecord{Name: r.Name, Addresses: append([]string(nil), r.Addresses...)})
			continue
		}
		seen := make(map[string]bool)
		for _, ip := range out.StaticDNS[i].Addresses {
			seen[ip] = true
		}
		for _, ip := range r.Addresses {
			if !seen[ip] {
				out.StaticDNS[i].Addresses = append(out.StaticDNS[i].Addresses, ip)
				seen[ip] = true
			}
		}
	}
	return out
}
