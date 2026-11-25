package relay

import (
	"context"
	"sync"
	"testing"
)

// brokenResourcesSource serves a snapshot the boundary refuses, like a VPN
// configuration that lists an address under "domains".
type brokenResourcesSource struct {
	*fakeSource
	mu  sync.Mutex
	bad bool
}

func (s *brokenResourcesSource) Snapshot(ctx context.Context) (SourceSnapshot, error) {
	s.mu.Lock()
	bad := s.bad
	s.mu.Unlock()
	snap, err := s.fakeSource.Snapshot(ctx)
	if err != nil {
		return snap, err
	}
	if bad {
		snap.Resources = &ResourceSnapshot{
			DomainRules: []DomainRule{{Domain: "203.0.113.9", PortMin: 443, PortMax: 443, Protocol: "tcp"}},
		}
	}
	return snap, nil
}

// The host must say why a share cannot be served, and only once per reason:
// the client only sees invalid_request, which is useless for the sharer.
func TestServerReportsAnUnservableSnapshotOnce(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	src := &brokenResourcesSource{fakeSource: newFakeSource(testSnapshot()), bad: true}
	s := &Server{source: src, logf: func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, format)
		mu.Unlock()
	}}
	for i := 0; i < 3; i++ {
		if _, err := s.snapshot(context.Background()); err == nil {
			t.Fatal("前置条件：坏快照应当被拒绝")
		}
	}
	mu.Lock()
	got := len(lines)
	mu.Unlock()
	if got != 1 {
		t.Fatalf("同一个失败记录了 %d 次", got)
	}

	// Recovering logs once as well.
	src.mu.Lock()
	src.bad = false
	src.mu.Unlock()
	if _, err := s.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got = len(lines)
	mu.Unlock()
	if got != 2 {
		t.Fatalf("恢复后日志条数 = %d，want 2", got)
	}
}
