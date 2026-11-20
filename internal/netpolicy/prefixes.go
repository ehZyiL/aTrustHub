package netpolicy

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"
)

var prohibitedCapturePrefixes = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4"),
}

// ResourcePrefixes converts bounded IPv4 ranges into their exact CIDR cover.
// Capture uses the result as a routing guard, not as access authorization.
func ResourcePrefixes(ranges []Range) ([]netip.Prefix, error) {
	compact, err := Compact(ranges)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	var captured uint64
	for _, r := range compact {
		lo, hi, _ := r.Addresses()
		if !lo.Is4() {
			return nil, errors.New("当前接管暂不支持 IPv6 内网资源")
		}
		low, high := lo.As4(), hi.As4()
		start, end := uint64(binary.BigEndian.Uint32(low[:])), uint64(binary.BigEndian.Uint32(high[:]))
		captured += end - start + 1
		if captured > 1<<20 {
			return nil, errors.New("接管范围超过 1048576 个 IPv4 地址，请缩小捕获范围或使用显式代理")
		}
		for start <= end {
			size := min(bits.TrailingZeros64(start), bits.Len64(end-start+1)-1)
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(start))
			prefix := netip.PrefixFrom(netip.AddrFrom4(b), 32-size)
			for _, reserved := range prohibitedCapturePrefixes {
				if prefix.Overlaps(reserved) {
					return nil, errors.New("VPN 资源包含映射或非单播范围，请使用显式代理")
				}
			}
			out = append(out, prefix)
			if len(out) > 2048 {
				return nil, errors.New("VPN 资源需要过多系统路由，请使用显式代理")
			}
			start += 1 << size
		}
	}
	return out, nil
}
