package main

import (
	"github.com/ehzyil/connect-hub/internal/relay/discovery"
	"github.com/ehzyil/connect-hub/internal/relay/process"
)

// setupLANDiscovery builds the publisher and the browser. The browser emits
// snapshots from its own goroutine, so they are parked here and picked up by
// the UI thread on its next frame.
func (a *app) setupLANDiscovery() {
	d := &lanDiscovery{}
	logf := func(format string, args ...any) { a.tunLogf("局域网发现："+format, args...) }
	emit := func(s discovery.Snapshot) {
		d.mu.Lock()
		if !d.shutDown && d.browsing && (d.pending == nil || s.Generation >= d.pending.Generation) {
			snapshot := s
			d.pending = &snapshot
		}
		d.mu.Unlock()
		a.invalidateCoalesced()
	}
	if a.discoveryBackend != nil {
		d.pub = discovery.NewPublisher(discovery.PublisherOptions{
			Backend: a.discoveryBackend, Logf: logf,
			OnChange: func(discovery.Status) { a.invalidateCoalesced() },
		})
		d.browser = discovery.NewBrowser(discovery.BrowserOptions{Backend: a.discoveryBackend, Logf: logf, Emit: emit})
	} else {
		runtime := process.NewDiscoveryRuntime(a.relayComponentPath(), logf, func(discovery.Status) {
			a.invalidateCoalesced()
		}, emit)
		d.pub = runtime.Publisher()
		d.browser = runtime.Browser()
	}
	a.lanDisc = d
}
