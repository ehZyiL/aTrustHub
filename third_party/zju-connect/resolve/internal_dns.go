package resolve

import "strings"

// EnableSplitDNS configures the bounded DNS query API. Existing aTrust packet
// resolver behavior is preserved; Hub resource routing selects strict dials.
func (r *Resolver) EnableSplitDNS(suffixes []string) {
	r.internalSuffixes = append([]string(nil), suffixes...)
}

func (r *Resolver) MustUseVPNDNS(host string) bool {
	host = normalizeHostname(host)
	if _, _, found := matchDomainResource(r.domainIndex, host); found {
		return true
	}
	for _, suffix := range r.internalSuffixes {
		suffix = strings.Trim(normalizeHostname(suffix), ".")
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	_, found := r.dnsResource[host]
	return found
}
