// Package netpolicy holds bounded address ranges shared by desktop capture
// backends. It contains no routing decisions or privileged operations.
package netpolicy

import (
	"errors"
	"net/netip"
	"sort"
)

const MaxRanges = 512

type Range struct {
	Min string `json:"min"`
	Max string `json:"max"`
}

func (r Range) Addresses() (netip.Addr, netip.Addr, error) {
	lo, e1 := netip.ParseAddr(r.Min)
	hi, e2 := netip.ParseAddr(r.Max)
	if e1 != nil || e2 != nil || lo.Zone() != "" || hi.Zone() != "" || lo.Is4In6() || hi.Is4In6() ||
		lo.BitLen() != hi.BitLen() || lo.Compare(hi) > 0 || lo.String() != r.Min || hi.String() != r.Max ||
		!lo.IsGlobalUnicast() || !hi.IsGlobalUnicast() {
		return netip.Addr{}, netip.Addr{}, errors.New("内网地址范围无效，当前软件接管需要明确的单播地址范围")
	}
	// A broad range whose endpoints are unicast can still cover loopback or
	// multicast space. Such a gateway policy cannot be used as a guard safely.
	for _, prefix := range excludedRanges {
		if prefix.Addr().BitLen() == lo.BitLen() && (prefix.Contains(lo) || prefix.Contains(hi) || lo.Compare(prefix.Addr()) <= 0 && hi.Compare(prefix.Addr()) >= 0) {
			return netip.Addr{}, netip.Addr{}, errors.New("内网地址范围覆盖本地或组播地址，当前软件接管不兼容")
		}
	}
	return lo, hi, nil
}

var excludedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func Validate(ranges []Range) error {
	if len(ranges) > MaxRanges {
		return errors.New("内网地址范围过多，当前软件接管最多支持 512 段")
	}
	for _, r := range ranges {
		if _, _, err := r.Addresses(); err != nil {
			return err
		}
	}
	return nil
}

// Compact removes overlap without widening the covered addresses. Both DNS
// records and gateway resources can describe the same address repeatedly.
func Compact(input []Range) ([]Range, error) {
	type parsed struct{ lo, hi netip.Addr }
	items := make([]parsed, 0, len(input))
	for _, r := range input {
		lo, hi, err := r.Addresses()
		if err != nil {
			return nil, err
		}
		items = append(items, parsed{lo, hi})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].lo.Compare(items[j].lo) < 0 })
	var merged []parsed
	for _, item := range items {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if last.lo.BitLen() == item.lo.BitLen() && (item.lo.Compare(last.hi) <= 0 || item.lo == last.hi.Next()) {
				if item.hi.Compare(last.hi) > 0 {
					last.hi = item.hi
				}
				continue
			}
		}
		merged = append(merged, item)
	}
	out := make([]Range, 0, len(merged))
	for _, r := range merged {
		out = append(out, Range{Min: r.lo.String(), Max: r.hi.String()})
	}
	return out, Validate(out)
}
