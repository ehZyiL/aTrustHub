package main

import (
	"context"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/relay"
)

// 选择网络的提示必须能让人一眼判断：子网是否和同事相同、是不是虚拟网卡、哪个是推荐。
func TestLANChoiceLabelExplainsTheChoice(t *testing.T) {
	subnets := map[string]string{
		"192.168.31.77": "192.168.31.0/24",
		"172.17.0.1":    "172.17.0.0/16",
		"10.8.6.130":    "10.8.6.130/32",
	}
	cands := newLANCandidates([]relay.Interface{
		{Name: "wlan0", IPv4: "192.168.31.77"},
		{Name: "docker0", IPv4: "172.17.0.1"},
		{Name: "wwan0", IPv4: "10.8.6.130"},
	}, func(ip string) (string, error) { return subnets[ip], nil })

	got := lanChoiceLabel(cands[0], true)
	for _, want := range []string{"wlan0", "192.168.31.77", "192.168.31.0/24", "推荐"} {
		if !strings.Contains(got, want) {
			t.Fatalf("physical label %q lacks %q", got, want)
		}
	}
	if !strings.Contains(lanChoiceLabel(cands[1], false), "虚拟网卡") {
		t.Fatalf("a container bridge was not marked virtual: %q", lanChoiceLabel(cands[1], false))
	}
	// A /32 can never host a colleague, whatever the adapter is called.
	if !strings.Contains(lanChoiceLabel(cands[2], false), "点对点") {
		t.Fatalf("a /32 address was not explained: %q", lanChoiceLabel(cands[2], false))
	}
	// Without a known subnet the label still identifies the address.
	bare := newLANCandidates([]relay.Interface{{Name: "wlan0", IPv4: "192.168.31.77"}}, nil)
	if label := lanChoiceLabel(bare[0], false); label != "wlan0 · 192.168.31.77" {
		t.Fatalf("label without subnet = %q", label)
	}
}

// 虚拟网卡的命名在每个平台都不同，识别不能只认 Linux 的 tun/docker。
func TestVirtualInterfaceCoversEveryPlatform(t *testing.T) {
	virtual := []string{
		// Linux
		"docker0", "veth1234", "br-f431a3", "virbr0", "tun0", "wg0", "tailscale0",
		"podman0", "incusbr0", "zt0",
		// macOS
		"utun3", "bridge0", "awdl0", "llw0", "gif0", "stf0", "ipsec0",
		// Windows (friendly names, incl. Hyper-V/WSL and VPN clients)
		"vEthernet (WSL)", "vEthernet (Default Switch)", "Local Area Connection* 2",
		"WireGuard Tunnel", "OpenVPN Wintun", "Tailscale", "NordLynx", "Hyper-V Virtual Ethernet Adapter",
		// This program's own adapters must never be offered as a LAN.
		"ECH-6f1a2b3c4d5e", "aTrustHub1", "ZJU Connect",
	}
	for _, name := range virtual {
		if !virtualInterface(name) {
			t.Errorf("%q was not recognised as virtual", name)
		}
	}
	physical := []string{"Ethernet", "Wi-Fi", "enp1s0", "wlan0", "en0", "以太网", "WLAN", "eth0"}
	for _, name := range physical {
		if virtualInterface(name) {
			t.Errorf("%q was wrongly treated as virtual", name)
		}
	}
}

// 推荐必须落在真实局域网网卡上；VPN 隧道即使占着默认路由也不能推荐。
func TestRecommendLAN(t *testing.T) {
	sn := func(cidrs map[string]string) func(string) (string, error) {
		return func(ip string) (string, error) { return cidrs[ip], nil }
	}
	cands := newLANCandidates([]relay.Interface{
		{Name: "tun0", IPv4: "10.8.6.130"},
		{Name: "docker0", IPv4: "172.17.0.1"},
		{Name: "enp1s0", IPv4: "192.168.31.61"},
		{Name: "eth0", IPv4: "10.0.0.5"},
	}, sn(map[string]string{
		"10.8.6.130":    "10.8.6.130/32",
		"172.17.0.1":    "172.17.0.0/16",
		"192.168.31.61": "192.168.31.0/24",
		"10.0.0.5":      "10.0.0.0/24",
	}))
	if got := recommendLAN(cands, "10.8.6.130"); got != 2 {
		t.Fatalf("recommended index = %d (%q), want the physical LAN", got, cands[got].iface.Name)
	}
	if got := recommendLAN(cands, "192.168.31.61"); got != 2 {
		t.Fatalf("recommended index = %d, want the default-route LAN", got)
	}
	// A VPN with a LAN-sized subnet but ranked virtual is still not recommended.
	onlyVirtual := newLANCandidates([]relay.Interface{{Name: "wg0", IPv4: "10.9.0.2"}}, sn(map[string]string{"10.9.0.2": "10.9.0.0/24"}))
	if got := recommendLAN(onlyVirtual, "10.9.0.2"); got != -1 {
		t.Fatalf("recommended a WireGuard tunnel (index %d)", got)
	}
	// Nothing LAN-sized: no recommendation at all rather than a wrong one.
	pointToPoint := newLANCandidates([]relay.Interface{{Name: "wwan0", IPv4: "10.8.6.130"}}, sn(map[string]string{"10.8.6.130": "10.8.6.130/32"}))
	if got := recommendLAN(pointToPoint, "10.8.6.130"); got != -1 {
		t.Fatalf("recommended a point-to-point address (index %d)", got)
	}
	if got := recommendLAN(nil, "192.168.1.2"); got != -1 {
		t.Fatalf("recommended with no candidates: %d", got)
	}
}

// 面板必须把「推荐」放在默认选中项，并显式标出虚拟网卡，否则「使用网络」就是一串
// 看不出差别的名字。
func TestLANSharePanelRecommendsTheReachableAdapter(t *testing.T) {
	list := lanAddresses{}.LANCandidates()
	if len(list) == 0 {
		t.Skip("no RFC1918 interface on this host")
	}
	a := testApp(t)
	withLANShare(t, a)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	a.openLANShare()
	tt := ui.NewTester(a.view, 880, 600)
	texts := strings.Join(tt.Texts(), "|")

	cands := newLANCandidates(list, relay.SubnetOfAddress)
	pick := recommendLAN(cands, outboundIPv4())
	if pick < 0 {
		t.Skip("no LAN-sized physical adapter on this host")
	}
	want := cands[pick].iface.IPv4
	if !strings.Contains(texts, "（推荐）") {
		t.Fatalf("the picker does not mark a recommendation: %s", texts)
	}
	subnet, err := relay.SubnetOfAddress(want)
	if err != nil {
		t.Fatalf("SubnetOfAddress(%s): %v", want, err)
	}
	if !strings.Contains(texts, subnet) {
		t.Fatalf("the picker does not show the subnet %s: %s", subnet, texts)
	}
	// The recommendation is what a first-time share uses, and it must never be a
	// virtual adapter: this host routes through a VPN tunnel, which is exactly the
	// wrong network for a colleague on the LAN.
	if a.lanShareUI.ipv4 != want {
		t.Fatalf("panel preselects %q, want the recommendation %q", a.lanShareUI.ipv4, want)
	}
	for _, cand := range list {
		if cand.IPv4 == a.lanShareUI.ipv4 && interfaceRank(cand.Name) > 0 {
			t.Fatalf("panel preselects the virtual adapter %s", cand.Name)
		}
	}
}

// 运行中的面板要说清「同事必须在哪个网段」，否则用户只能靠猜。
func TestRunningSharePanelShowsTheSubnetHint(t *testing.T) {
	list := lanAddresses{}.LANCandidates()
	if len(list) == 0 {
		t.Skip("no RFC1918 interface on this host")
	}
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Add(model.AccessPoint{ID: "p1", Name: "公司 VPN", Protocol: model.ProtocolATrust, Server: "vpn.example.com", Port: 443, Username: "u", InPool: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.setConfig(a.store.Config())
	a.mgr.Apply(a.cfg)
	echo, closeEcho := echoListenerForTest(t)
	defer closeEcho()
	ctrl := installLANShareWith(t, a, &appTestSink{names: map[string]string{"p1": "公司 VPN"}, echo: echo}, lanAddresses{})
	cands := newLANCandidates(list, relay.SubnetOfAddress)
	pick := recommendLAN(cands, outboundIPv4())
	if pick < 0 {
		t.Skip("no LAN-sized physical adapter on this host")
	}
	pickAddr := cands[pick].iface.IPv4
	if err := ctrl.Enable(context.Background(), relay.EnableOptions{PointID: "p1", PreferredIPv4: pickAddr}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	a.openLANShare()
	tt := ui.NewTester(a.view, 880, 620)
	texts := strings.Join(tt.Texts(), "|")
	subnet, err := relay.SubnetOfAddress(pickAddr)
	if err != nil {
		t.Fatalf("SubnetOfAddress(%s): %v", pickAddr, err)
	}
	if !strings.Contains(texts, "所在网段") || !strings.Contains(texts, subnet) {
		t.Fatalf("the running panel does not show the subnet %s: %s", subnet, texts)
	}
	if !strings.Contains(texts, "同一网段") {
		t.Fatalf("the running panel does not explain the colleague requirement: %s", texts)
	}
}
