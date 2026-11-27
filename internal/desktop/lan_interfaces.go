package desktop

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
	relayfirewall "github.com/ehzyil/connect-hub/internal/relay/firewall"
)

// lanAddresses enumerates the addresses a share may bind: up, non-loopback
// interfaces with a private IPv4 address. Interface names only order the list;
// they are never the sole test.
type lanAddresses struct{}

func (lanAddresses) LANCandidates() []relay.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []relay.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || !model.RFC1918(ip) {
				continue
			}
			out = append(out, relay.Interface{Name: iface.Name, IPv4: ip.String()})
		}
	}
	// Physical interfaces first: a docker bridge or a VPN adapter is a poor
	// default for a colleague on the office Wi-Fi, but it is not refused.
	sort.SliceStable(out, func(i, j int) bool {
		return interfaceRank(out[i].Name) < interfaceRank(out[j].Name)
	})
	return out
}

func interfaceRank(name string) int {
	if virtualInterface(name) {
		return 1
	}
	return 0
}

// virtualInterface reports whether an adapter is a container bridge, a VM switch
// or a VPN tunnel rather than the LAN a colleague sits on.
//
// The names differ per platform and Windows uses localized friendly names
// ("以太网", "WLAN"), so this list can only be a hint: it orders the picker and
// labels the entries. Whether an address can actually host a share is decided by
// name-independent facts (a LAN-sized subnet), never by this function alone.
func virtualInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{
		// Containers, VM switches, host bridges (Linux / Windows / macOS).
		"docker", "veth", "br-", "virbr", "vnet", "vethernet", "vmnet", "vboxnet",
		"lxc", "cni", "podman", "incus", "mpqemu", "bridge", "tap",
		// Windows: Hyper-V/WSL switches and VPN clients.
		"loopback", "npcap", "hyper-v", "local area connection*",
		// This program's own adapters: the Windows capture device (ECH-<id>, which
		// is normally on 198.19.0.0/16 and so already fails the RFC1918 test) and
		// the upstream Wintun names (aTrustHubN, ZJU Connect). Naming them here
		// means the classification does not rest on the address pool alone.
		"ech-", "atrusthub", "zju connect",
		// Tunnels and VPNs (Linux tun0/wg0/tailscale0, macOS utunN,
		// Windows Wintun/WireGuard/OpenVPN adapters).
		"tun", "utun", "wg", "wintun", "wireguard", "openvpn", "tailscale", "zerotier",
		"nordlynx", "proton", "surfshark", "mullvad", "nebula", "hamachi", "n2n", "zt",
		"isatap", "teredo", "6to4",
		// macOS point-to-point / Apple wireless direct.
		"awdl", "llw", "gif", "stf", "ipsec", "pdp_ip",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// lanCandidate is one selectable address plus what the panel needs to explain it.
type lanCandidate struct {
	iface   relay.Interface
	subnet  string
	lanSize bool // the subnet has room for other hosts
	virtual bool
}

// newLANCandidates annotates the enumerated addresses. subnetOf is injected so
// the classification can be tested without depending on the host's interfaces.
func newLANCandidates(list []relay.Interface, subnetOf func(string) (string, error)) []lanCandidate {
	out := make([]lanCandidate, 0, len(list))
	for _, cand := range list {
		subnet := ""
		if subnetOf != nil {
			if got, err := subnetOf(cand.IPv4); err == nil {
				subnet = got
			}
		}
		out = append(out, lanCandidate{
			iface:   cand,
			subnet:  subnet,
			lanSize: lanSizedCIDR(subnet),
			virtual: virtualInterface(cand.Name),
		})
	}
	return out
}

// lanSizedCIDR reports whether a subnet can hold another host. A /31 or /32 is a
// point-to-point link (a tunnel), not a LAN, whatever the adapter is called.
func lanSizedCIDR(cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits != 0 && ones <= bits-2
}

// recommendLAN returns the index to preselect, or -1 when no candidate is a real
// LAN. It prefers the default route's address, but only when that address is a
// LAN-sized non-virtual adapter: a VPN tunnel or a container bridge is very often
// the default route, and recommending it would send the share to a network no
// colleague can reach.
func recommendLAN(cands []lanCandidate, outbound string) int {
	for i, c := range cands {
		if c.iface.IPv4 == outbound && !c.virtual && c.lanSize {
			return i
		}
	}
	for i, c := range cands {
		if !c.virtual && c.lanSize {
			return i
		}
	}
	return -1
}

// lanChoiceLabel is what the picker shows for one candidate.
func lanChoiceLabel(cand lanCandidate, recommended bool) string {
	label := cand.iface.Name + " · " + cand.iface.IPv4
	if cand.subnet != "" {
		label += " · " + cand.subnet
	}
	switch {
	case recommended:
		label += "（推荐）"
	case cand.virtual:
		label += "（虚拟网卡，其他设备通常不可达）"
	case cand.subnet != "" && !cand.lanSize:
		// Unknown subnet must not be described as point-to-point; only a
		// measured /31 or /32 is.
		label += "（点对点地址，其他设备不可达）"
	}
	return label
}

// relayInterfaceChoices returns the label -> address mapping the panel offers.
//
// A colleague can only reach an address inside their own subnet, so each choice
// shows the subnet and the most likely one is marked: the default route when it
// is a real LAN, otherwise the first LAN-sized physical adapter.
func (a *app) relayInterfaceChoices() ([]string, map[string]relay.Interface) {
	cands := newLANCandidates(lanAddresses{}.LANCandidates(), relayfirewall.SubnetOfAddress)
	pick := recommendLAN(cands, outboundIPv4())
	labels := make([]string, 0, len(cands))
	byLabel := make(map[string]relay.Interface, len(cands))
	for i, cand := range cands {
		label := lanChoiceLabel(cand, i == pick)
		labels = append(labels, label)
		byLabel[label] = cand.iface
	}
	return labels, byLabel
}

// outboundIPv4 reports the local address of the default route. A connected UDP
// socket performs the route lookup without sending a packet, so this costs
// nothing and works on every platform.
func outboundIPv4() string {
	conn, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1, never contacted
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return ""
	}
	return addr.IP.To4().String()
}

// browseInterfaces returns the exact interfaces to browse on. Virtual adapters
// and point-to-point links are not browsing targets: they are what makes "I
// found my own VPN" a bug report. The classification is the share panel's own
// (newLANCandidates), so the two pickers cannot disagree about which adapter is
// a LAN.
func (a *app) browseInterfaces(choice string) []discovery.Interface {
	// Browsing must work on a machine that never shared anything: the address
	// list comes from the machine, not from the share controller.
	source := a.localLANBrowseCandidates()
	seen := make(map[string]bool)
	var out []discovery.Interface
	for _, cand := range source {
		if cand.iface.IPv4 == "" || seen[cand.iface.Name] {
			continue
		}
		if !browsableAdapter(cand) {
			continue
		}
		if choice != "" && cand.iface.Name != choice {
			continue
		}
		// One socket per adapter: the transport opens its multicast group per
		// interface, not per address, so a second address of the same adapter
		// would only duplicate every packet.
		seen[cand.iface.Name] = true
		// The subnet is what later rejects an announcement reflected from
		// another network.
		out = append(out, discovery.Interface{
			Name: cand.iface.Name, IPv4: cand.iface.IPv4, Subnet: cand.subnet,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].IPv4 < out[j].IPv4
	})
	// A browser per interface is a real cost, so a machine with dozens of
	// adapters is bounded; the picker still lists every one of them.
	if len(out) > maxBrowsedInterfaces {
		out = out[:maxBrowsedInterfaces]
	}
	return out
}

// browsableAdapter reports whether one enumerated address is a LAN another
// device could answer on. The share panel refuses the same two cases when it
// recommends an address, so a user cannot be told an adapter is a LAN in one
// place and not in the other.
func browsableAdapter(cand lanCandidate) bool {
	if cand.virtual {
		return false
	}
	// A /31 or /32 is a point-to-point link: a tunnel, whatever the adapter is
	// called. Browsing it opens a socket that can only ever see itself.
	return cand.lanSize
}

// maxBrowsedInterfaces bounds how many adapters browse at once.
const maxBrowsedInterfaces = 8

// allLANInterfaces is the uncapped list behind the network picker. It applies
// the same filter as browseInterfaces, so every choice it offers is one the
// browser can actually open.
func (a *app) allLANInterfaces() []discovery.Interface {
	var out []discovery.Interface
	seen := map[string]bool{}
	for _, cand := range a.localLANBrowseCandidates() {
		if cand.iface.IPv4 == "" || seen[cand.iface.Name] || !browsableAdapter(cand) {
			continue
		}
		seen[cand.iface.Name] = true
		out = append(out, discovery.Interface{
			Name: cand.iface.Name, IPv4: cand.iface.IPv4, Subnet: cand.subnet,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// localLANBrowseCandidates returns the machine's LAN addresses annotated the way
// the share panel annotates its own picker (subnet, LAN-sized, virtual), and it
// owns that cache: enumerating interfaces is a syscall per address, a subnet
// lookup is a full enumeration, and the discovery page renders per frame.
func (a *app) localLANBrowseCandidates() []lanCandidate {
	now := time.Now()
	if a.lanDisc != nil {
		a.lanDisc.mu.Lock()
		if len(a.lanDisc.localCands) > 0 && now.Sub(a.lanDisc.localAt) < time.Second {
			cached := append([]lanCandidate(nil), a.lanDisc.localCands...)
			a.lanDisc.mu.Unlock()
			return cached
		}
		a.lanDisc.mu.Unlock()
	}
	list := lanAddresses{}.LANCandidates()
	cands := newLANCandidates(list, relayfirewall.SubnetOfAddress)
	if a.lanDisc != nil {
		// Both copies come from this one list, written under one lock: a reader
		// can never observe an annotation set that belongs to another list.
		a.lanDisc.mu.Lock()
		a.lanDisc.localAddrs = append([]relay.Interface(nil), list...)
		a.lanDisc.localCands = append([]lanCandidate(nil), cands...)
		a.lanDisc.localAt = now
		a.lanDisc.mu.Unlock()
	}
	return cands
}

// localLANCandidates is the plain address list, for callers that only need to
// recognise this machine's own addresses.
func (a *app) localLANCandidates() []relay.Interface {
	cands := a.localLANBrowseCandidates()
	out := make([]relay.Interface, 0, len(cands))
	for _, cand := range cands {
		out = append(out, cand.iface)
	}
	return out
}
