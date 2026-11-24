package discovery

import (
	"context"
	"sort"
	"testing"
	"time"
)

// TestLiveDiscoveryLatency records the first-result latency over 20 rounds on a
// real multicast socket. The acceptance target in the plan is 2-5 seconds on a
// normal network; this asserts a generous bound and logs the distribution so the
// number in the report comes from a measurement, not from a guess.
//
// It runs on one machine, so it measures the protocol and the event plumbing,
// not radio behaviour or AP isolation.
func TestLiveDiscoveryLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("短模式跳过真实组播时延测量")
	}
	ifi, ok := liveInterface(t)
	if !ok {
		t.Skip("没有可用的局域网网卡，跳过时延测量（需实机覆盖）")
	}
	backend := NewMDNSBackend(nil)
	const rounds = 20
	var samples []time.Duration
	for i := 0; i < rounds; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		snapshots := make(chan Snapshot, 8)
		b := NewBrowser(BrowserOptions{Backend: backend, Emit: func(s Snapshot) {
			select {
			case snapshots <- s:
			default:
			}
		}})
		if err := b.Start([]Interface{ifi}); err != nil {
			cancel()
			_ = b.Close()
			t.Skipf("无法在 %s 上浏览：%v", ifi, err)
		}
		ann := Announcement{
			Generation:      uint64(i + 1),
			ShareID:         fakeShareID(1000 + i),
			Name:            "时延测量",
			ProtocolVersion: 1,
			Interface:       ifi,
			Address:         ifi.IPv4,
			Port:            23456,
		}
		start := time.Now()
		reg, err := backend.Advertise(ctx, ann)
		if err != nil {
			cancel()
			_ = b.Close()
			t.Skipf("无法发布：%v", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		found := false
		for time.Now().Before(deadline) && !found {
			select {
			case snap := <-snapshots:
				for _, cand := range snap.Candidates {
					if cand.ShareID == ann.ShareID {
						found = true
					}
				}
			case <-time.After(20 * time.Millisecond):
			}
		}
		if !found {
			_ = reg.Close()
			_ = b.Close()
			cancel()
			t.Fatalf("第 %d 轮 10 秒内没有发现", i+1)
		}
		samples = append(samples, time.Since(start))
		_ = reg.Close()
		_ = b.Close()
		cancel()
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[len(samples)/2]
	p95 := samples[len(samples)*95/100]
	t.Logf("首次发现时延（%d 轮，接口 %s）：min=%v median=%v p95=%v max=%v",
		rounds, ifi, samples[0], median, p95, samples[len(samples)-1])
	if p95 > 3*time.Second {
		t.Fatalf("p95 时延 %v 超出目标（2–5 秒）", p95)
	}
}
