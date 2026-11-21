package localapps

import (
	"errors"
	"net/netip"

	"github.com/ehzyil/connect-hub/internal/netpolicy"
	"github.com/ehzyil/connect-hub/internal/workeripc"
)

// CaptureNetworks identifies known internal addresses, for rejecting protocols
// this capture backend cannot carry. It never grants VPN access to an address.
func CaptureNetworks(resources *workeripc.ResourceSnapshot) ([]netpolicy.Range, error) {
	if resources == nil {
		return nil, errors.New("连接核心未提供资源信息，无法启用软件接管")
	}
	var ranges []netpolicy.Range
	for _, r := range resources.IPRules {
		ranges = append(ranges, netpolicy.Range{Min: r.Min, Max: r.Max})
	}
	for _, record := range resources.StaticDNS {
		for _, ip := range record.Addresses {
			a, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, errors.New("网关返回了无效的静态 DNS 地址")
			}
			a = a.Unmap()
			ranges = append(ranges, netpolicy.Range{Min: a.String(), Max: a.String()})
		}
	}
	return netpolicy.Compact(ranges)
}
