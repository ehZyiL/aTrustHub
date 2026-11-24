package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

// liveInterface returns the first real RFC1918 interface of this machine, or
// false when the sandbox has none. The live test is skipped instead of failing,
// because a container without a LAN is not a product defect.
func liveInterface(t *testing.T) (Interface, bool) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		return Interface{}, false
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			candidate := Interface{Name: ifi.Name, IPv4: ip.String()}
			if candidate.Valid() {
				return candidate, true
			}
		}
	}
	return Interface{}, false
}

// TestLiveMulticastRoundTrip exercises the real sockets: one advertiser and one
// browser on the same interface. Two instances of this app on one machine is
// exactly the developer scenario, and multicast loopback makes it possible
// without a second computer.
func TestLiveMulticastRoundTrip(t *testing.T) {
	ifi, ok := liveInterface(t)
	if !ok {
		t.Skip("没有可用的局域网网卡，跳过真实组播测试（打包验收需实机覆盖）")
	}
	if testing.Short() {
		t.Skip("短模式跳过真实组播测试")
	}
	backend := NewMDNSBackend(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ann := Announcement{
		Generation:      1,
		ShareID:         "BBBBBBBBBBBBBBBBBBBBBB",
		Name:            "组播自测",
		ProtocolVersion: 1,
		Interface:       ifi,
		Address:         ifi.IPv4,
		Port:            23457,
	}
	// Browsing starts first so the advertiser's first announcement is heard,
	// and so is a later re-announcement.
	snapshots := make(chan Snapshot, 16)
	b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(s Snapshot) {
		select {
		case snapshots <- s:
		default:
		}
	}})
	defer b.Close()
	if err := b.Start([]Interface{ifi}); err != nil {
		t.Skipf("无法在 %s 上开始浏览：%v", ifi, err)
	}
	reg, err := backend.Advertise(ctx, ann)
	if err != nil {
		t.Skipf("无法在 %s 上发布：%v", ifi, err)
	}
	defer reg.Close()

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		for _, cand := range b.Snapshot().Candidates {
			if cand.ShareID == ann.ShareID && cand.Port == ann.Port && cand.Address == ann.Address {
				// A goodbye must remove it again without waiting for the TTL.
				if err := reg.Close(); err != nil {
					t.Fatalf("撤销失败：%v", err)
				}
				gone := time.Now().Add(5 * time.Second)
				for time.Now().Before(gone) {
					seen := false
					for _, c := range b.Snapshot().Candidates {
						if c.ShareID == ann.ShareID {
							seen = true
						}
					}
					if !seen {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
				t.Fatal("goodbye 之后候选仍在列表里")
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("真实组播下没有发现 %s:23457（接口 %s）", ann.Address, ifi)
}
