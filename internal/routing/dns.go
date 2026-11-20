package routing

import (
	"fmt"
	"net/netip"
)

// DNS has no business port; its default owner is configured separately.
type DNSBinding struct {
	ID        string `json:"id"`
	Pattern   string `json:"pattern"`
	GatewayID string `json:"gatewayId"`
}

func (b DNSBinding) Validate() error {
	if b.ID == "" || b.GatewayID == "" || !ValidPattern(b.Pattern) {
		return fmt.Errorf("DNS 默认归属无效")
	}
	if _, e := netip.ParseAddr(b.Pattern); e == nil {
		return fmt.Errorf("DNS 归属必须使用域名")
	}
	if _, e := netip.ParsePrefix(b.Pattern); e == nil {
		return fmt.Errorf("DNS 归属不能使用 IP 范围")
	}
	return nil
}

func DecideDNS(name, boundID string, gateways []Gateway, bindings []DNSBinding) Decision {
	d := Decision{Action: "blocked"}
	host, err := NormalizeHost(name)
	if err != nil {
		d.Reason = "无效 DNS 名称"
		return d
	}
	if _, err = netip.ParseAddr(host); err == nil {
		d.Reason = "DNS 请求必须使用名称"
		return d
	}
	d.Target = host
	if boundID == "" {
		for _, b := range bindings {
			if b.Validate() == nil && MatchPattern(b.Pattern, host) {
				boundID = b.GatewayID
				d.RuleID = b.ID
				break
			}
		}
	}
	d.GatewayID = boundID
	best := 0
	var owners []Gateway
	for _, g := range gateways {
		if boundID != "" && g.ID != boundID {
			continue
		}
		score, _, _ := claim(g.Current, host, 0, "dns")
		known, _, _ := claim(g.Known, host, 0, "dns")
		if known > score {
			score = known
		}
		if score == 0 {
			continue
		}
		if score > best {
			owners = nil
			best = score
		}
		if score == best {
			owners = append(owners, g)
		}
	}
	for _, g := range owners {
		d.Owners = append(d.Owners, g.ID)
		d.Matches = append(d.Matches, matches(g, host, 0, "dns")...)
	}
	if len(owners) == 0 {
		d.Reason = "没有已知内网 DNS 归属"
		return d
	}
	if len(owners) > 1 {
		d.Reason = "DNS 归属冲突，请设置该域名的默认网关"
		return d
	}
	g := owners[0]
	if score, _, _ := claim(g.Current, host, 0, "dns"); !g.Online || score == 0 {
		d.Reason = "DNS 所属网关离线或已撤销该名称"
		return d
	}
	d.Action, d.Reason = "vpn", "由名称归属网关解析；DNS 答案不授予连接权限"
	d.Candidates = []Candidate{{ID: g.ID, Name: g.Name, Version: g.Version, Generation: g.Generation, NeedsResolution: true}}
	return d
}
