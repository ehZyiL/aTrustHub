package wincapture

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"

	"github.com/qy/easyconnect/internal/dnsmapping"
	"github.com/qy/easyconnect/internal/netpolicy"
)

type Route struct {
	Prefix    netip.Prefix
	Interface uint32
	Metric    uint64
}

// OriginalRoute deliberately includes virtual interfaces such as Tailscale.
// The caller reads current routes, excluding only this capture adapter.
func OriginalRoute(destination netip.Addr, routes []Route, excluded uint32) (Route, error) {
	var best Route
	found, ambiguous := false, false
	for _, r := range routes {
		if r.Interface == 0 || r.Interface == excluded || !r.Prefix.Contains(destination) {
			continue
		}
		if !found || r.Prefix.Bits() > best.Prefix.Bits() || r.Prefix.Bits() == best.Prefix.Bits() && r.Metric < best.Metric {
			best, found, ambiguous = r, true, false
		} else if r.Prefix.Bits() == best.Prefix.Bits() && r.Metric == best.Metric && r.Interface != best.Interface {
			ambiguous = true
		}
	}
	if !found {
		return Route{}, errors.New("目标原出口已不可用")
	}
	if ambiguous {
		return Route{}, errors.New("目标有多个等价原出口，无法安全选择")
	}
	return best, nil
}

// ResourcePrefixes converts exact gateway ranges without widening them. A
// full/default route is never accepted. IPv6 capture is not available yet.
func ResourcePrefixes(ranges []netpolicy.Range) ([]netip.Prefix, error) {
	compact, err := netpolicy.Compact(ranges)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, r := range compact {
		lo, hi, _ := r.Addresses()
		if !lo.Is4() {
			return nil, errors.New("Windows 软件接管暂不支持 IPv6 内网资源")
		}
		low, high := lo.As4(), hi.As4()
		start, end := uint64(binary.BigEndian.Uint32(low[:])), uint64(binary.BigEndian.Uint32(high[:]))
		for start <= end {
			size := min(bits.TrailingZeros64(start), bits.Len64(end-start+1)-1)
			if size >= 32 {
				return nil, errors.New("Windows 软件接管不允许默认路由")
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(start))
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32-size))
			if len(out) > 2048 {
				return nil, errors.New("VPN 资源需要过多系统路由，请使用显式代理")
			}
			start += 1 << size
		}
	}
	return out, nil
}

// The adapter subnet and domain alias pool are separate. Adapter addresses
// must never be returned to applications as VPN destinations.
func choosePrefixes(routes []Route, resources []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	available := func(candidate netip.Prefix) bool {
		for _, r := range routes {
			if r.Prefix.Bits() >= 15 && r.Prefix.Overlaps(candidate) {
				return false
			}
		}
		for _, r := range resources {
			if r.Overlaps(candidate) {
				return false
			}
		}
		return true
	}
	var adapter, aliases netip.Prefix
	occupied := append([]netip.Prefix(nil), resources...)
	for _, r := range routes {
		if r.Prefix.Bits() >= 15 {
			occupied = append(occupied, r.Prefix)
		}
	}
	aliases, _ = dnsmapping.Choose(occupied, nil)
	for i := 0; i < 256; i++ {
		candidate := netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, byte(i), 0}), 30)
		if available(candidate) {
			adapter = candidate
			break
		}
	}
	if !adapter.IsValid() || !aliases.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, errors.New("虚拟地址与已有路由或代理地址池冲突，请使用显式代理")
	}
	return adapter, aliases, nil
}
