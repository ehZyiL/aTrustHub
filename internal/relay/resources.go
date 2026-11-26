package relay

import (
	contract "github.com/ehzyil/connect-hub/internal/relay/contract"
)

// dnsNote describes the DNS side of one snapshot for the diagnostic report. A
// share without a DNS server is not a failure, but a colleague who then cannot
// resolve an intranet name must be able to tell "no DNS offered" from "DNS
// broken".
func dnsNote(s *ResourceSnapshot) string {
	if s == nil || s.DNSServer == "" {
		return "；本次分享不提供 DNS，内网域名需由本机解析"
	}
	return "；DNS 经分享主机 " + s.DNSServer
}

const MaxIPRules = contract.MaxIPRules

const MaxDomainRules = contract.MaxDomainRules

const MaxStaticDNS = contract.MaxStaticDNS

const MaxInternalDomains = contract.MaxInternalDomains

const MaxSnapshotBytes = contract.MaxSnapshotBytes

const MaxDomainLength = contract.MaxDomainLength

type IPRule = contract.IPRule

type DomainRule = contract.DomainRule

type DNSRecord = contract.DNSRecord

type ResourceSnapshot = contract.ResourceSnapshot

func DomainUsable(name string) bool { return contract.DomainUsable(name) }
