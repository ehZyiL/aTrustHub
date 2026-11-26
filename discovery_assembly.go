package main

import (
	"github.com/ehzyil/connect-hub/internal/relay/discovery"
)

// setupLANDiscovery builds the publisher and the browser. The browser emits
// snapshots from its own goroutine, so they are parked here and picked up by
// the UI thread on its next frame.
func (a *app) setupLANDiscovery() {
	backend := a.discoveryBackend
	if backend == nil {
		backend = discovery.NewMDNSBackend(func(format string, args ...any) {
			a.tunLogf("局域网发现："+format, args...)
		})
	}
	d := &lanDiscovery{}
	d.pub = discovery.NewPublisher(discovery.PublisherOptions{
		Backend: backend,
		Logf: func(format string, args ...any) {
			a.tunLogf("局域网发现："+format, args...)
		},
		OnChange: func(discovery.Status) {
			a.invalidateCoalesced()
		},
	})
	d.browser = discovery.NewBrowser(discovery.BrowserOptions{
		Backend: backend,
		Logf: func(format string, args ...any) {
			a.tunLogf("局域网发现："+format, args...)
		},
		Emit: func(s discovery.Snapshot) {
			d.mu.Lock()
			if !d.shutDown && d.browsing && (d.pending == nil || s.Generation >= d.pending.Generation) {
				snapshot := s
				d.pending = &snapshot
			}
			d.mu.Unlock()
			a.invalidateCoalesced()
		},
	})
	a.lanDisc = d
}
