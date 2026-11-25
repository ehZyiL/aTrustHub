package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
)

// Resource limits of the v1 protocol. They are protocol bounds, not measured
// performance figures.
const (
	MaxIPRules         = 4096
	MaxDomainRules     = 4096
	MaxStaticDNS       = 4096
	MaxInternalDomains = 256
	MaxSnapshotBytes   = 2 << 20
	MaxDomainLength    = 253
)

// IPRule is an authorized IPv4 range with a port range and protocol.
type IPRule struct {
	Min      string `json:"min"`
	Max      string `json:"max"`
	PortMin  int    `json:"portMin"`
	PortMax  int    `json:"portMax"`
	Protocol string `json:"protocol"`
}

// DomainRule is an authorized domain suffix with a port range and protocol.
type DomainRule struct {
	Domain   string `json:"domain"`
	PortMin  int    `json:"portMin"`
	PortMax  int    `json:"portMax"`
	Protocol string `json:"protocol"`
}

// DNSRecord is a static name-to-address declaration. It grants attribution and
// name service only, never a business port.
type DNSRecord struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// ResourceSnapshot is the effective published scope of one access point, as the
// sharing host sees it after its own disabled-app switches. It never carries VPN
// login data, private proxy addresses, tokens or local synthetic mappings.
type ResourceSnapshot struct {
	IPRules         []IPRule     `json:"ipRules,omitempty"`
	DomainRules     []DomainRule `json:"domainRules,omitempty"`
	StaticDNS       []DNSRecord  `json:"staticDNS,omitempty"`
	InternalDomains []string     `json:"internalDomains,omitempty"`
	DNSServer       string       `json:"dnsServer,omitempty"`
}

// Clone deep-copies a snapshot.
func (s *ResourceSnapshot) Clone() *ResourceSnapshot {
	if s == nil {
		return nil
	}
	out := *s
	out.IPRules = append([]IPRule(nil), s.IPRules...)
	out.DomainRules = append([]DomainRule(nil), s.DomainRules...)
	out.InternalDomains = append([]string(nil), s.InternalDomains...)
	out.StaticDNS = make([]DNSRecord, len(s.StaticDNS))
	for i, r := range s.StaticDNS {
		out.StaticDNS[i] = DNSRecord{Name: r.Name, Addresses: append([]string(nil), r.Addresses...)}
	}
	return &out
}

// EntryCount is the total number of rules, for limits and diagnostics.
func (s *ResourceSnapshot) EntryCount() int {
	if s == nil {
		return 0
	}
	return len(s.IPRules) + len(s.DomainRules) + len(s.StaticDNS) + len(s.InternalDomains)
}

// Empty reports whether the snapshot authorizes and attributes nothing.
func (s *ResourceSnapshot) Empty() bool { return s.EntryCount() == 0 }

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

// Normalize lowercases and sorts in a fixed order, so two equal scopes always
// produce the same revision regardless of the order the VPN reported them.
func (s *ResourceSnapshot) Normalize() {
	if s == nil {
		return
	}
	for i := range s.IPRules {
		r := &s.IPRules[i]
		r.Min = normalizeIP(r.Min)
		r.Max = normalizeIP(r.Max)
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	}
	sort.SliceStable(s.IPRules, func(i, j int) bool {
		a, b := s.IPRules[i], s.IPRules[j]
		if a.Min != b.Min {
			return a.Min < b.Min
		}
		if a.Max != b.Max {
			return a.Max < b.Max
		}
		if a.PortMin != b.PortMin {
			return a.PortMin < b.PortMin
		}
		if a.PortMax != b.PortMax {
			return a.PortMax < b.PortMax
		}
		return a.Protocol < b.Protocol
	})
	s.IPRules = dedupeIPRules(s.IPRules)

	for i := range s.DomainRules {
		r := &s.DomainRules[i]
		r.Domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Domain)), ".")
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	}
	sort.SliceStable(s.DomainRules, func(i, j int) bool {
		a, b := s.DomainRules[i], s.DomainRules[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.PortMin != b.PortMin {
			return a.PortMin < b.PortMin
		}
		if a.PortMax != b.PortMax {
			return a.PortMax < b.PortMax
		}
		return a.Protocol < b.Protocol
	})
	s.DomainRules = dedupeDomainRules(s.DomainRules)

	for i := range s.StaticDNS {
		r := &s.StaticDNS[i]
		r.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
		seen := make(map[string]bool, len(r.Addresses))
		kept := make([]string, 0, len(r.Addresses))
		for _, a := range r.Addresses {
			a = normalizeIP(a)
			if a == "" || seen[a] {
				continue
			}
			seen[a] = true
			kept = append(kept, a)
		}
		sort.Strings(kept)
		r.Addresses = kept
	}
	sort.SliceStable(s.StaticDNS, func(i, j int) bool { return s.StaticDNS[i].Name < s.StaticDNS[j].Name })

	for i := range s.InternalDomains {
		s.InternalDomains[i] = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s.InternalDomains[i])), ".")
	}
	sort.Strings(s.InternalDomains)
	s.InternalDomains = dedupeStrings(s.InternalDomains)
	s.DNSServer = normalizeIP(s.DNSServer)
}

func normalizeIP(value string) string {
	if ip, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
		return ip.Unmap().String()
	}
	return strings.TrimSpace(value)
}

func dedupeIPRules(in []IPRule) []IPRule {
	out := in[:0]
	for i, r := range in {
		if i > 0 && out[len(out)-1] == r {
			continue
		}
		out = append(out, r)
	}
	return out
}

func dedupeDomainRules(in []DomainRule) []DomainRule {
	out := in[:0]
	for i, r := range in {
		if i > 0 && out[len(out)-1] == r {
			continue
		}
		out = append(out, r)
	}
	return out
}

func dedupeStrings(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i > 0 && out[len(out)-1] == s {
			continue
		}
		out = append(out, s)
	}
	return out
}

// PublishTCP narrows the snapshot to what v1 can actually enforce: TCP. A
// UDP-only rule grants nothing, and "all" only narrows to TCP; it never widens
// the published capability set.
func (s *ResourceSnapshot) PublishTCP() *ResourceSnapshot {
	if s == nil {
		return nil
	}
	out := s.Clone()
	ips := make([]IPRule, 0, len(out.IPRules))
	for _, r := range out.IPRules {
		switch r.Protocol {
		case "tcp":
			ips = append(ips, r)
		case "all":
			r.Protocol = "tcp"
			ips = append(ips, r)
		}
	}
	out.IPRules = ips
	domains := make([]DomainRule, 0, len(out.DomainRules))
	for _, r := range out.DomainRules {
		switch r.Protocol {
		case "tcp":
			domains = append(domains, r)
		case "all":
			r.Protocol = "tcp"
			domains = append(domains, r)
		}
	}
	out.DomainRules = domains
	out.Normalize()
	return out
}

// Validate checks a peer-supplied snapshot field by field. TLS pinning proves
// who sent it, not that the content is sane: an unverified rule could otherwise
// widen the local entry's scope.
func (s *ResourceSnapshot) Validate() error {
	if s == nil {
		return NewError(CodeInvalidRequest, "资源快照缺失")
	}
	if len(s.IPRules) > MaxIPRules || len(s.DomainRules) > MaxDomainRules || len(s.StaticDNS) > MaxStaticDNS || len(s.InternalDomains) > MaxInternalDomains {
		return NewError(CodeInvalidRequest, "资源快照条目超过上限")
	}
	for _, r := range s.IPRules {
		lo, errLo := netip.ParseAddr(r.Min)
		hi, errHi := netip.ParseAddr(r.Max)
		if errLo != nil || errHi != nil {
			return NewError(CodeInvalidRequest, "资源 IP 范围无效")
		}
		lo, hi = lo.Unmap(), hi.Unmap()
		if !lo.Is4() || !hi.Is4() {
			return NewError(CodeInvalidRequest, "资源 IP 范围必须是 IPv4")
		}
		if lo.Compare(hi) > 0 {
			return NewError(CodeInvalidRequest, "资源 IP 范围起止颠倒")
		}
		if err := validatePorts(r.PortMin, r.PortMax); err != nil {
			return err
		}
		if !validProtocol(r.Protocol) {
			return NewError(CodeInvalidRequest, "资源协议无效")
		}
		if isCaptureAlias(lo) || isCaptureAlias(hi) {
			return NewError(CodeInvalidRequest, "资源包含本机会话合成地址")
		}
	}
	for _, r := range s.DomainRules {
		if err := validateDomain(r.Domain); err != nil {
			return err
		}
		if err := validatePorts(r.PortMin, r.PortMax); err != nil {
			return err
		}
		if !validProtocol(r.Protocol) {
			return NewError(CodeInvalidRequest, "资源协议无效")
		}
	}
	for _, r := range s.StaticDNS {
		if err := validateDomain(r.Name); err != nil {
			return err
		}
		if len(r.Addresses) == 0 {
			return NewError(CodeInvalidRequest, "静态 DNS 记录缺少地址")
		}
		for _, a := range r.Addresses {
			ip, err := netip.ParseAddr(a)
			if err != nil || !ip.Unmap().Is4() {
				return NewError(CodeInvalidRequest, "静态 DNS 地址无效")
			}
		}
	}
	for _, d := range s.InternalDomains {
		if err := validateDomain(d); err != nil {
			return err
		}
	}
	if s.DNSServer != "" {
		ip, err := netip.ParseAddr(s.DNSServer)
		if err != nil || !ip.Unmap().Is4() {
			return NewError(CodeInvalidRequest, "DNS 服务器地址无效")
		}
	}
	if b, err := json.Marshal(s); err == nil && len(b) > MaxSnapshotBytes {
		return NewError(CodeInvalidRequest, "资源快照超过大小上限")
	}
	return nil
}

func validatePorts(min, max int) error {
	if min < 1 || max > 65535 || min > max {
		return NewError(CodeInvalidRequest, "资源端口范围无效")
	}
	return nil
}

func validProtocol(p string) bool { return p == "tcp" || p == "udp" || p == "all" }

// DomainUsable reports whether a name may travel as a domain rule. Real VPN
// configurations sometimes list an address under "domains"; those entries are
// meaningless as names and are dropped at the boundary instead of failing a
// whole share.
func DomainUsable(name string) bool { return validateDomain(name) == nil }

// DropUnusableDomains removes domain rules, internal-domain entries and static
// DNS names that cannot be expressed as names. It returns how many were dropped
// so the caller can log once.
//
// Dropping a name only ever narrows what is proxied (the address itself, if it
// matters, belongs in an IP rule), so this is safe on both the publishing and
// the receiving side. Everything else in a snapshot - ranges, ports, size -
// stays strict.
//
// Static DNS is included on purpose: Validate runs the same name check on
// StaticDNS[].Name, so leaving that field alone kept "资源域名不能是 IP 地址"
// reachable for every colleague even after the domain rules were cleaned.
func (s *ResourceSnapshot) DropUnusableDomains() int {
	if s == nil {
		return 0
	}
	dropped := 0
	kept := s.DomainRules[:0]
	for _, r := range s.DomainRules {
		if !DomainUsable(r.Domain) {
			dropped++
			continue
		}
		kept = append(kept, r)
	}
	s.DomainRules = kept
	domains := s.InternalDomains[:0]
	for _, d := range s.InternalDomains {
		if !DomainUsable(d) {
			dropped++
			continue
		}
		domains = append(domains, d)
	}
	s.InternalDomains = domains
	records := s.StaticDNS[:0]
	for _, r := range s.StaticDNS {
		if !DomainUsable(r.Name) {
			dropped++
			continue
		}
		records = append(records, r)
	}
	s.StaticDNS = records
	return dropped
}

// validateDomain accepts a bare DNS suffix, including the "*." wildcard form the
// VPN resolver uses. IPs are not domain rules, and a rule must not smuggle a
// port or a path.
func validateDomain(name string) error {
	n := strings.TrimPrefix(strings.TrimPrefix(name, "*."), ".")
	n = strings.TrimSuffix(n, ".")
	if n == "" || len(n) > MaxDomainLength {
		return NewError(CodeInvalidRequest, "资源域名无效")
	}
	if strings.ContainsAny(n, " /\\:@?#\t\r\n*") {
		return NewError(CodeInvalidRequest, "资源域名无效")
	}
	if _, err := netip.ParseAddr(n); err == nil {
		return NewError(CodeInvalidRequest, "资源域名不能是 IP 地址")
	}
	for _, label := range strings.Split(n, ".") {
		if label == "" || len(label) > 63 {
			return NewError(CodeInvalidRequest, "资源域名无效")
		}
	}
	return nil
}

// captureAliasPrefix is the local synthetic block. A peer snapshot must never
// inject it: those addresses are session-local mapping identities.
var captureAliasPrefix = netip.MustParsePrefix("198.18.0.0/15")

func isCaptureAlias(ip netip.Addr) bool { return captureAliasPrefix.Contains(ip) }

// Revision is the SHA-256 of the normalized effective published content,
// including the capability set. It identifies one epoch's content; it is not the
// existing resourceVersion(rawResources), which identifies the mapping pool.
func (s *ResourceSnapshot) Revision(caps Capabilities) string {
	normalized := s.Clone()
	normalized.Normalize()
	payload := struct {
		Snapshot     *ResourceSnapshot `json:"resources"`
		Capabilities []string          `json:"capabilities"`
	}{normalized, caps.Names()}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
