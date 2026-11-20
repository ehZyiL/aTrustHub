package routing

import "fmt"

// Policies select exits in saved order. Gateway ACLs remain the authority.
type Policy struct {
	ID        string `json:"id"`
	Pattern   string `json:"pattern"`
	Protocol  string `json:"protocol"`
	PortMin   int    `json:"portMin"`
	PortMax   int    `json:"portMax"`
	Action    string `json:"action"`
	GatewayID string `json:"gatewayId,omitempty"`
}

func (p Policy) Validate() error {
	if p.ID == "" || !ValidPattern(p.Pattern) || p.PortMin < 1 || p.PortMax > 65535 || p.PortMin > p.PortMax || (p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "all") {
		return fmt.Errorf("路由策略格式无效")
	}
	switch p.Action {
	case "auto", "direct", "block":
		if p.GatewayID != "" {
			return fmt.Errorf("只有指定网关策略可以包含网关")
		}
	case "gateway":
		if p.GatewayID == "" {
			return fmt.Errorf("请选择网关")
		}
	default:
		return fmt.Errorf("路由动作无效")
	}
	return nil
}

func applyPolicy(r Request, host string, port int, network string, policies []Policy) (Request, string, string, string) {
	for _, p := range policies {
		if p.Validate() != nil || !MatchPattern(p.Pattern, host) || !authorized(p.Protocol, p.PortMin, p.PortMax, port, network) {
			continue
		}
		switch p.Action {
		case "block":
			return r, p.ID, "blocked", "用户策略阻止访问"
		case "direct":
			if r.Mapped {
				return r, p.ID, "blocked", "合成地址不能转交原网络"
			}
			return r, p.ID, "direct", "用户明确指定原网络"
		case "gateway":
			if r.GatewayID != "" && r.GatewayID != p.GatewayID {
				return r, p.ID, "blocked", "用户策略与入口绑定的网关冲突"
			}
			r.GatewayID = p.GatewayID
			r.AllowUnmanaged = false
		}
		return r, p.ID, "", ""
	}
	return r, "", "", ""
}
