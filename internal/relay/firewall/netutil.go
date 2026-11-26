package firewall

import (
	"net"
)

// privateIPv4 reports whether ip is RFC1918 private-use IPv4 unicast. The share
// listener and the share code both refuse anything else: loopback, unspecified,
// link-local and multicast are not LAN-reachable addresses for a colleague.
func privateIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 10 ||
		(v4[0] == 172 && v4[1]&0xf0 == 16) ||
		(v4[0] == 192 && v4[1] == 168)
}
