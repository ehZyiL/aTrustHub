package workeripc

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode"
)

type flowCarrier interface{ FlowResult() FlowResult }

// ConnectionResult uses only structured core data. A successful legacy dial
// has an unknown route; the SOCKS server accepting it is not proof of VPN use.
func ConnectionResult(conn net.Conn, err error) FlowResult {
	if c, ok := conn.(flowCarrier); ok && err == nil {
		return c.FlowResult()
	}
	var c flowCarrier
	if errors.As(err, &c) {
		return c.FlowResult()
	}
	r := FlowResult{Route: "unknown"}
	if err != nil {
		r.Failure = "connect"
		var n net.Error
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, net.ErrClosed):
			r.Failure = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			r.Failure = "timeout"
		case errors.As(err, &n) && n.Timeout():
			r.Failure = "timeout"
		}
	}
	return r
}

func ValidFlowResult(r FlowResult) bool {
	if !flowTarget(r.Target) || (r.DialAddress != "" && !flowTarget(r.DialAddress)) {
		return false
	}
	switch r.Route {
	case "vpn", "direct", "blocked", "unknown":
	default:
		return false
	}
	switch r.Rule {
	case "", "domain_resource", "ip_resource", "default", "forced", "acl", "dns", "alias":
	default:
		return false
	}
	switch r.Failure {
	case "", "dns", "alias", "denied", "canceled", "timeout", "refused", "unreachable", "connect", "busy":
	default:
		return false
	}
	if r.Route == "blocked" && r.Failure == "" {
		return false
	}
	if len(r.Domain) > 253 || strings.ContainsAny(r.Domain, " /?#@\\") || strings.IndexFunc(r.Domain, unicode.IsControl) >= 0 {
		return false
	}
	if r.Rule == "ip_resource" && (net.ParseIP(r.IPMin).To4() == nil || net.ParseIP(r.IPMax).To4() == nil) {
		return false
	}
	if r.Rule == "ip_resource" || r.Rule == "domain_resource" {
		if r.PortMin < 0 || r.PortMax > 65535 || r.PortMax < r.PortMin {
			return false
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "all" {
			return false
		}
	}
	return true
}

func flowTarget(s string) bool {
	host, port, err := net.SplitHostPort(s)
	n, perr := strconv.Atoi(port)
	return err == nil && perr == nil && n > 0 && n <= 65535 && host != "" && len(host) <= 253 &&
		!strings.ContainsAny(host, " /?#@\\") && strings.IndexFunc(host, unicode.IsControl) < 0
}
