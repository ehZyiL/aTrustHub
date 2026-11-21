package capture

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"

	"github.com/ehZyiL/connect-hub/internal/dnsmapping"
	"github.com/ehZyiL/connect-hub/internal/netpolicy"
)

// chooseAliasPrefix allocates from kernel state while the caller holds the
// network transaction lock. Broad transport routes (default or a TUN /2) are
// original egress paths, not evidence that their whole space is a Fake-IP pool.
// A specific route inside the benchmark block, an address literal in nftables,
// or another still-live lease reserves that space conservatively.
func chooseAliasPrefix(state kernelState, resources []netpolicy.Range, reserved []string, required ...string) (string, error) {
	if err := netpolicy.Validate(resources); err != nil {
		return "", err
	}
	block := netip.MustParsePrefix("198.18.0.0/15")
	var occupied []netip.Prefix
	for _, raw := range reserved {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p != p.Masked() || !p.Addr().Is4() {
			return "", errors.New("capture: invalid existing alias reservation")
		}
		occupied = append(occupied, p)
	}
	for _, r := range state.routes {
		dst, ok := r["dst"].(string)
		if !ok || dst == "default" {
			continue
		}
		p, err := netip.ParsePrefix(dst)
		if err != nil {
			if ip, e := netip.ParseAddr(dst); e == nil && ip.Is4() {
				p = netip.PrefixFrom(ip, 32)
			} else {
				continue
			}
		}
		if p.Bits() >= block.Bits() && p.Overlaps(block) {
			occupied = append(occupied, p)
		}
	}
	// Include maps/sets as well as rule literals. Only values that actually
	// parse as addresses count; marks, ports and table IDs cannot become CIDRs.
	var inspect func(any)
	inspect = func(v any) {
		switch x := v.(type) {
		case string:
			if p, err := netip.ParsePrefix(x); err == nil && p.Overlaps(block) {
				occupied = append(occupied, p)
				return
			}
			if a, err := netip.ParseAddr(x); err == nil && block.Contains(a) {
				occupied = append(occupied, netip.PrefixFrom(a, 32))
				return
			}
			if pieces := strings.Split(x, "-"); len(pieces) == 2 {
				lo, e1 := netip.ParseAddr(pieces[0])
				hi, e2 := netip.ParseAddr(pieces[1])
				if e1 == nil && e2 == nil && (block.Contains(lo) || block.Contains(hi)) {
					// An opaque textual range is uncommon in nft JSON. Reserve
					// the whole block rather than incorrectly infer its bounds.
					occupied = append(occupied, block)
				}
			}
		case []any:
			for _, child := range x {
				inspect(child)
			}
		case map[string]any:
			if prefix, ok := x["prefix"].(map[string]any); ok {
				addr, _ := prefix["addr"].(string)
				bits, valid := number(prefix["len"])
				if a, err := netip.ParseAddr(addr); err == nil && a.Is4() && valid && bits <= 32 {
					p := netip.PrefixFrom(a, int(bits)).Masked()
					if p.Overlaps(block) {
						occupied = append(occupied, p)
					}
				}
			}
			if endpoints, ok := x["range"].([]any); ok && len(endpoints) == 2 {
				left, _ := endpoints[0].(string)
				right, _ := endpoints[1].(string)
				lo, e1 := netip.ParseAddr(left)
				hi, e2 := netip.ParseAddr(right)
				if e1 == nil && e2 == nil && lo.Is4() && hi.Is4() && lo.Compare(hi) <= 0 {
					for i := 0; i < 32; i++ {
						p := aliasCandidate(i)
						if rangesOverlapPrefix(lo, hi, p) {
							occupied = append(occupied, p)
						}
					}
				}
			}
			for _, child := range x {
				inspect(child)
			}
		}
	}
	for _, entry := range state.nft {
		inspect(entry)
	}
	var prefix netip.Prefix
	var err error
	if len(required) > 0 && required[0] != "" {
		prefix, err = dnsmapping.ChooseRequired(occupied, resources, required[0])
	} else {
		prefix, err = dnsmapping.Choose(occupied, resources)
	}
	if err != nil {
		return "", err
	}
	return prefix.String(), nil
}

func aliasCandidate(i int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18 + byte(i/16), byte((i % 16) * 16), 0}), 20)
}
func rangesOverlapPrefix(lo, hi netip.Addr, p netip.Prefix) bool {
	base := p.Addr().As4()
	n := binary.BigEndian.Uint32(base[:]) | uint32(1<<(32-p.Bits())-1)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return lo.Compare(netip.AddrFrom4(b)) <= 0 && hi.Compare(p.Addr()) >= 0
}
