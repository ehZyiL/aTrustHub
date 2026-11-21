package vpn

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ehZyiL/connect-hub/internal/routing"
)

// BenchmarkRouteLogging isolates the access log from network and GUI work.
func BenchmarkRouteLogging(b *testing.B) {
	req := routing.Request{Entry: "system-tun", Network: "tcp"}
	session := routedSession{gen: 1, version: "fixture"}
	session.id = "fixture"
	var decisions [512]routing.Decision
	for i := range decisions {
		decisions[i] = routing.Decision{Target: fmt.Sprintf("192.0.2.1:%d", 20000+i), RuleID: "fixture", Reason: "owned", Owners: []string{"fixture"}}
	}
	for _, tc := range []struct {
		name string
		bus  bool
		file bool
		span int
	}{
		{name: "disabled", span: len(decisions)},
		{name: "repeat", bus: true, file: true, span: 1},
		{name: "varied_memory", bus: true, span: len(decisions)},
		{name: "varied_file", bus: true, file: true, span: len(decisions)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			m := &Manager{}
			if tc.bus {
				m.bus = NewLogBus(500)
			}
			if tc.file {
				f, err := os.Create(filepath.Join(b.TempDir(), "app.log"))
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = f.Close() })
				m.bus.SetSink(f)
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				m.logRoute(req, decisions[i%tc.span], session, 1, time.Millisecond, nil)
				i++
			}
		})
	}
}
