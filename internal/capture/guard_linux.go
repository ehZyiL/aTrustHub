package capture

import (
	"fmt"
	"strings"
)

func (l ruleLease) guardName() string  { return "echg_" + l.ID }
func (l ruleLease) guardOwner() string { return l.owner() + ":guard" }

// Unsupported internal UDP/IPv6 fails at the selected socket's output hook.
// Public traffic and other scopes are unaffected. This is intentionally not a
// system-wide kill switch and is removed together with the TCP capture lease.
func (l ruleLease) guardScript() string {
	if len(l.Networks) == 0 {
		return ""
	}
	var v4, v6 []string
	for _, r := range l.Networks {
		lo, hi, _ := r.Addresses() // validated before installing or recovering
		value := lo.String()
		if lo != hi {
			value += "-" + hi.String()
		}
		if lo.Is4() {
			v4 = append(v4, value)
		} else {
			v6 = append(v6, value)
		}
	}
	var b strings.Builder
	n := l.guardName()
	fmt.Fprintf(&b, "create table inet %s { comment %q; }\n", n, l.guardOwner())
	fmt.Fprintf(&b, "add chain inet %s out { type filter hook output priority -151; policy accept; }\n", n)
	selector := fmt.Sprintf("meta skuid %d socket cgroupv2 level %d %q", l.UID, len(strings.Split(l.Group, "/")), l.Group)
	if len(v4) > 0 {
		fmt.Fprintf(&b, "add set inet %s internal4 { type ipv4_addr; flags interval; auto-merge; elements = { %s }; }\n", n, strings.Join(v4, ", "))
		fmt.Fprintf(&b, "add rule inet %s out %s ip daddr @internal4 meta l4proto udp reject with icmp type port-unreachable\n", n, selector)
	}
	if len(v6) > 0 {
		fmt.Fprintf(&b, "add set inet %s internal6 { type ipv6_addr; flags interval; auto-merge; elements = { %s }; }\n", n, strings.Join(v6, ", "))
		fmt.Fprintf(&b, "add rule inet %s out %s ip6 daddr @internal6 reject with icmpv6 type admin-prohibited\n", n, selector)
	}
	return b.String()
}

func (l ruleLease) guardRuleCount() int {
	v4, v6 := false, false
	for _, r := range l.Networks {
		a, _, _ := r.Addresses()
		if a.Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	n := 0
	if v4 {
		n++
	}
	if v6 {
		n++
	}
	return n
}
