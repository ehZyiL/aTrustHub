// Package routing makes resource ownership decisions without DNS or dialing.
package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/qy/easyconnect/internal/workeripc"
	"golang.org/x/net/idna"
)

type Request struct {
	Network         string
	Address         string
	GatewayID       string // trusted binding supplied by the caller, never SOCKS metadata
	AllowUnmanaged  bool   // bound browser/proxy may use the original network for unknown targets
	Mapped          bool   // trusted capture adapter has checked this session's assigned alias prefix
	Entry           string // caller-supplied trusted entry label for diagnostics
	OriginalAddress string // verified mapped domain and port, never supplied by a public proxy
}

type Gateway struct {
	ID, Name       string
	Generation     int
	Version        string
	Online, Strict bool
	UDP            bool // Strict IPv4 UDP has been negotiated for this generation.
	Excluded       bool // aggregate exclusion; explicit bindings still work
	Current        *workeripc.ResourceSnapshot
	Known          *workeripc.ResourceSnapshot // attribution only; never authorizes a dial
}

type Candidate struct {
	ID, Name, Version string
	Generation        int
	NeedsResolution   bool
}

type Decision struct {
	Action     string // vpn, direct, blocked
	Target     string
	Reason     string
	RuleID     string
	GatewayID  string // effective binding after user policy
	Owners     []string
	Candidates []Candidate
	Matches    []Match
}

// Group explicitly declares equivalent exits for one target policy. Sharing
// a CIDR or domain is insufficient to infer this relationship.
type Group struct {
	ID          string   `json:"id"`
	Pattern     string   `json:"pattern"`
	Protocol    string   `json:"protocol"`
	PortMin     int      `json:"portMin"`
	PortMax     int      `json:"portMax"`
	Gateways    []string `json:"gateways"`
	DNSFailover bool     `json:"dnsFailover,omitempty"` // Explicitly equivalent name service; new queries may use an online backup.
}

func NormalizeHost(host string) (string, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String(), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.ContainsAny(host, " /\\:@*\t\r\n") {
		return "", fmt.Errorf("无效目标主机")
	}
	host, err := idna.Lookup.ToASCII(host)
	if err != nil || len(host) > 253 {
		return "", fmt.Errorf("无效目标域名")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("无效目标域名")
		}
	}
	return host, nil
}

func ParseRequest(r Request) (host string, port int, network string, err error) {
	host, p, e := net.SplitHostPort(r.Address)
	if e != nil {
		return "", 0, "", fmt.Errorf("目标必须包含主机和端口")
	}
	port, e = strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return "", 0, "", fmt.Errorf("目标端口无效")
	}
	host, err = NormalizeHost(host)
	network = r.Network
	if network == "tcp4" {
		network = "tcp"
	}
	if network == "udp4" {
		network = "udp"
	}
	if network != "tcp" && network != "udp" && network != "tcp6" && network != "udp6" {
		err = fmt.Errorf("不支持的传输协议")
	}
	return
}

// Domain rules follow the gateway resolver: bare names include label-boundary
// subdomains; *.name and .name exclude the apex and allow multiple labels.
func DomainSpecificity(pattern, host string) int {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	wild := strings.HasPrefix(pattern, "*.") || strings.HasPrefix(pattern, ".")
	pattern = strings.TrimPrefix(strings.TrimPrefix(pattern, "*"), ".")
	name, err := NormalizeHost(pattern)
	if err != nil {
		return 0
	}
	if host == name && !wild {
		return len(name)*2 + 1
	}
	if strings.HasSuffix(host, "."+name) {
		return len(name)*2 + 1
	}
	return 0
}

func ipMatch(rule workeripc.IPRule, host string) bool {
	ip, e := netip.ParseAddr(host)
	lo, e1 := netip.ParseAddr(rule.Min)
	hi, e2 := netip.ParseAddr(rule.Max)
	if e != nil || e1 != nil || e2 != nil {
		return false
	}
	ip, lo, hi = ip.Unmap(), lo.Unmap(), hi.Unmap()
	return ip.BitLen() == lo.BitLen() && lo.BitLen() == hi.BitLen() && lo.Compare(ip) <= 0 && hi.Compare(ip) >= 0
}

func authorized(protocol string, min, max, port int, network string) bool {
	return min > 0 && max <= 65535 && min <= port && port <= max && (protocol == network || protocol == "all")
}

// claim separates ownership from authorization. DNS declarations never grant
// a port: they require final validation of the answer by the strict worker.
func claim(s *workeripc.ResourceSnapshot, host string, port int, network string) (score int, allow, dnsOnly bool) {
	if s == nil {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		for _, r := range s.IPRules {
			if ipMatch(r, host) {
				score = 1
				allow = allow || authorized(r.Protocol, r.PortMin, r.PortMax, port, network)
			}
		}
		// Static DNS addresses are known internal, but only IP ACLs authorize
		// a bare-address request that has lost its original domain identity.
		for _, r := range s.StaticDNS {
			for _, ip := range r.Addresses {
				a, e := netip.ParseAddr(ip)
				if e == nil && a.Unmap().String() == host {
					score = 1
				}
			}
		}
		return
	}
	for _, r := range s.DomainRules {
		if n := DomainSpecificity(r.Domain, host); n > 0 {
			if n > score {
				score = n
			}
			allow = allow || authorized(r.Protocol, r.PortMin, r.PortMax, port, network)
		}
	}
	if score > 0 {
		return
	}
	for _, suffix := range s.InternalDomains {
		if n := DomainSpecificity(suffix, host); n > score {
			score = n
			dnsOnly = true
		}
	}
	for _, r := range s.StaticDNS {
		name, e := NormalizeHost(r.Name)
		if e == nil && name == host {
			score = len(host)*2 + 2
			dnsOnly = true
		}
	}
	return
}

func Decide(r Request, gateways []Gateway, groups []Group, policies ...Policy) Decision {
	d := Decision{Action: "blocked"}
	host, port, network, err := ParseRequest(r)
	if err != nil {
		d.Reason = err.Error()
		return d
	}
	d.Target = net.JoinHostPort(host, strconv.Itoa(port))
	if ip, e := netip.ParseAddr(host); e == nil && netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(ip) && !r.Mapped {
		d.Reason = "合成地址缺少有效的会话映射身份，请重新解析"
		return d
	}
	var action, reason string
	policyHost := host
	if r.Mapped {
		original, originalPort, _, e := ParseRequest(Request{Network: r.Network, Address: r.OriginalAddress})
		if e != nil || originalPort != port {
			d.Reason = "映射缺少有效原始目标"
			return d
		}
		policyHost = original
	}
	r, d.RuleID, action, reason = applyPolicy(r, policyHost, port, network, policies)
	d.GatewayID = r.GatewayID
	if action != "" {
		d.Action, d.Reason = action, reason
		return d
	}
	if r.Mapped {
		ip, e := netip.ParseAddr(host)
		if e != nil || !netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(ip) || r.GatewayID == "" || network != "tcp" && network != "udp" {
			d.Reason = "无效的映射身份"
			return d
		}
		for _, g := range gateways {
			if g.ID == r.GatewayID && g.Online && g.Strict && (network != "udp" || g.UDP) {
				d.Action, d.Reason = "vpn", "映射绑定当前会话，核心再次校验身份和授权"
				d.Owners = []string{g.ID}
				d.Candidates = []Candidate{{ID: g.ID, Name: g.Name, Generation: g.Generation, Version: g.Version}}
				return d
			}
		}
		d.Reason = "映射所属会话不可用"
		return d
	}
	if ip, e := netip.ParseAddr(host); e == nil && netip.MustParsePrefix(workeripc.CaptureAliasBlock).Contains(ip) {
		d.Reason = "合成地址缺少有效的会话映射身份，请重新解析"
		return d
	}
	var owners []Gateway
	best := 0
	for _, g := range gateways {
		if r.GatewayID != "" && r.GatewayID != g.ID {
			continue
		}
		score, _, _ := claim(g.Current, host, port, network)
		known, _, _ := claim(g.Known, host, port, network)
		if known > score {
			score = known
		}
		if score == 0 {
			continue
		}
		if score > best {
			best = score
			owners = nil
		}
		if score == best {
			owners = append(owners, g)
		}
	}
	if len(owners) == 0 {
		if r.GatewayID != "" {
			if r.AllowUnmanaged {
				unbound := r
				unbound.GatewayID, unbound.AllowUnmanaged = "", false
				if original := Decide(unbound, gateways, groups); original.Action == "direct" {
					return original
				}
			}
			d.Reason = "指定网关未授权该目标"
			return d
		}
		d.Action, d.Reason = "direct", "目标不属于已知受管资源"
		return d
	}
	for _, g := range owners {
		d.Owners = append(d.Owners, g.ID)
		d.Matches = append(d.Matches, matches(g, host, port, network)...)
	}
	if len(owners) > 1 && !equivalent(groups, owners, host, port, network) {
		d.Reason = "资源归属冲突，请指定网关或配置同业务出口"
		return d
	}
	if ip, e := netip.ParseAddr(host); e == nil && !ip.Is4() {
		d.Reason = "内网 IPv6 尚不支持"
		return d
	}
	if network != "tcp" && network != "udp" {
		d.Reason = "内网业务协议尚不支持，仅支持 IPv4 TCP"
		return d
	}
	for _, g := range owners {
		_, allow, dnsOnly := claim(g.Current, host, port, network)
		if !g.Online || (g.Excluded && r.GatewayID != g.ID) {
			d.Reason = "所属网关不可用"
			continue
		}
		if !allow && !dnsOnly {
			d.Reason = "当前资源端口或协议未授权"
			continue
		}
		if !g.Strict {
			d.Reason = "所属网关缺少严格 VPN 拨号能力，请更新配套核心"
			continue
		}
		if network == "udp" && !g.UDP {
			d.Reason = "所属网关没有可用的 IPv4 UDP 隧道，或核心版本不匹配"
			continue
		}
		d.Candidates = append(d.Candidates, Candidate{ID: g.ID, Name: g.Name, Version: g.Version, Generation: g.Generation, NeedsResolution: dnsOnly})
	}
	if len(d.Candidates) == 0 {
		return d
	}
	d.Action, d.Reason = "vpn", "按资源归属选择已授权网关"
	return d
}

func equivalent(groups []Group, owners []Gateway, host string, port int, network string) bool {
	for _, group := range groups {
		if !authorized(group.Protocol, group.PortMin, group.PortMax, port, network) || !MatchPattern(group.Pattern, host) {
			continue
		}
		found := true
		for _, owner := range owners {
			if !contains(group.Gateways, owner.ID) {
				found = false
				break
			}
		}
		if found {
			return true
		}
	}
	return false
}

func MatchPattern(pattern, host string) bool {
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		ip, e := netip.ParseAddr(host)
		return e == nil && prefix.Contains(ip)
	}
	if ip, err := netip.ParseAddr(pattern); err == nil {
		return ip.Unmap().String() == host
	}
	return DomainSpecificity(pattern, host) > 0
}

func ValidPattern(pattern string) bool {
	if p, err := netip.ParsePrefix(pattern); err == nil {
		return p == p.Masked()
	}
	if _, err := netip.ParseAddr(pattern); err == nil {
		return true
	}
	name := pattern
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	} else {
		name = strings.TrimPrefix(name, ".")
	}
	_, err := NormalizeHost(name)
	return err == nil && pattern != ""
}

func contains(values []string, value string) bool {
	for _, s := range values {
		if s == value {
			return true
		}
	}
	return false
}

func Version(s *workeripc.ResourceSnapshot) string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// Rendezvous ranks stable gateway IDs. There is no mutable index-based cache;
// every new decision is made against the current snapshot/version and ACL.
func Rendezvous(candidates []Candidate, target string) {
	score := func(id string) [32]byte { return sha256.Sum256([]byte(target + "\x00" + id)) }
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := score(candidates[i].ID), score(candidates[j].ID)
		return strings.Compare(string(a[:]), string(b[:])) > 0
	})
}
