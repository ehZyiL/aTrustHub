package vpn

import (
	"net"
	"sort"
	"strings"

	"github.com/ehzyil/connect-hub/internal/workeripc"
	zcclient "github.com/mythologyli/zju-connect/client"
)

func cloneResources(in *workeripc.ResourceSnapshot) *workeripc.ResourceSnapshot {
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

// Merge only attribution history. Callers must use Current for authorization.
func rememberResources(known, current *workeripc.ResourceSnapshot) *workeripc.ResourceSnapshot {
	if current == nil {
		return known
	}
	if known == nil {
		return cloneResources(current)
	}
	out := cloneResources(known)
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

func networkResources(ips []zcclient.IPResource, domains zcclient.DomainResources, dns map[string][]net.IP, server string, suffixes []string) *workeripc.ResourceSnapshot {
	s := &workeripc.ResourceSnapshot{Tunnel: "ipv4-l3", DNSServer: server, InternalDomains: append([]string(nil), suffixes...)}
	for _, r := range ips {
		s.IPRules = append(s.IPRules, workeripc.IPRule{Min: r.IPMin.String(), Max: r.IPMax.String(), PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol})
	}
	names := make([]string, 0, len(domains))
	for name := range domains {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, r := range domains[name] {
			s.DomainRules = append(s.DomainRules, workeripc.DomainRule{Domain: name, PortMin: r.PortMin, PortMax: r.PortMax, Protocol: r.Protocol})
		}
	}
	names = names[:0]
	for name := range dns {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := workeripc.DNSRecord{Name: strings.ToLower(strings.TrimSuffix(name, "."))}
		for _, ip := range dns[name] {
			r.Addresses = append(r.Addresses, ip.String())
		}
		s.StaticDNS = append(s.StaticDNS, r)
	}
	return s
}

// filterDisabledAppsSnapshot drops the rules that belong to applications the
// user switched off. The application id travels inside the snapshot (worker
// protocol v7), so this one function covers every protocol: aTrust in-process and
// the EasyConnect worker alike.
//
// A rule without an app id is kept: dropping what cannot be attributed would
// silently take tunnel access away from applications the user never touched.
func filterDisabledAppsSnapshot(snapshot *workeripc.ResourceSnapshot, disabled []string) *workeripc.ResourceSnapshot {
	if snapshot == nil || len(disabled) == 0 {
		return snapshot
	}
	off := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		if id != "" {
			off[id] = true
		}
	}
	if len(off) == 0 {
		return snapshot
	}
	out := *snapshot
	keptIP := make([]workeripc.IPRule, 0, len(snapshot.IPRules))
	for _, rule := range snapshot.IPRules {
		if !off[rule.AppID] {
			keptIP = append(keptIP, rule)
		}
	}
	out.IPRules = keptIP
	keptDomain := make([]workeripc.DomainRule, 0, len(snapshot.DomainRules))
	for _, rule := range snapshot.DomainRules {
		if !off[rule.AppID] {
			keptDomain = append(keptDomain, rule)
		}
	}
	out.DomainRules = keptDomain
	return &out
}

func cloneSessionInfo(in SessionInfo) SessionInfo {
	in.Resources = cloneResources(in.Resources)
	in.Apps = cloneApps(in.Apps)
	in.NodeGroups = append([]string(nil), in.NodeGroups...)
	in.BestNodes = cloneMap(in.BestNodes)
	return in
}
