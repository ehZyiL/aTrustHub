package desktop

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
)

type blockedImportBrowser struct {
	mu             sync.Mutex
	entered        chan struct{}
	release        chan struct{}
	starts         []string
	generation     uint64
	live           bool
	firstErr       error
	candidates     []discovery.Candidate
	refreshEntered chan struct{}
	refreshRelease chan struct{}
}

func (b *blockedImportBrowser) Start(ifaces []discovery.Interface) error {
	b.mu.Lock()
	b.starts = append(b.starts, ifaces[0].Name)
	first := len(b.starts) == 1
	b.generation++
	b.mu.Unlock()
	if first {
		close(b.entered)
		<-b.release
		if b.firstErr != nil {
			return b.firstErr
		}
	}
	b.mu.Lock()
	b.live = true
	b.mu.Unlock()
	return nil
}

func (b *blockedImportBrowser) Close() error {
	b.mu.Lock()
	b.live = false
	b.mu.Unlock()
	return nil
}

func (b *blockedImportBrowser) Shutdown() error { return b.Close() }
func (b *blockedImportBrowser) Err() string     { return "" }

func (b *blockedImportBrowser) Refresh() error {
	if b.refreshEntered != nil {
		close(b.refreshEntered)
		<-b.refreshRelease
	}
	return nil
}

func (b *blockedImportBrowser) Snapshot() discovery.Snapshot {
	// The process runtime's startup mutex can also block snapshot reads.
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	return discovery.Snapshot{Generation: b.generation, Candidates: append([]discovery.Candidate(nil), b.candidates...)}
}

func cacheImportInterfaces(d *lanDiscovery) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.localAt = time.Now()
	d.localCands = []lanCandidate{
		{iface: relay.Interface{Name: "LAN", IPv4: "192.168.1.2"}, subnet: "192.168.1.0/24", lanSize: true},
		{iface: relay.Interface{Name: "Wi-Fi", IPv4: "192.168.2.2"}, subnet: "192.168.2.0/24", lanSize: true},
	}
}

func asyncDiscoveryApp(t *testing.T, firstErr error) (*app, *blockedImportBrowser, func()) {
	t.Helper()
	a := testApp(t)
	a.discoveryBackend = newTestDiscoveryBackend()
	a.setupLANDiscovery()
	b := &blockedImportBrowser{entered: make(chan struct{}), release: make(chan struct{}), firstErr: firstErr}
	a.lanDisc.browser = b
	cacheImportInterfaces(a.lanDisc)
	var once sync.Once
	release := func() { once.Do(func() { close(b.release) }) }
	t.Cleanup(func() { release(); a.shutdownLANDiscovery() })
	return a, b, release
}

func waitLANBrowse(t *testing.T, a *app) {
	t.Helper()
	waitCondition(t, "discovery startup result", func() bool {
		a.drainLANDiscovery()
		return !a.lanDisc.ui.starting
	})
}

func importUIAction(t *testing.T, release func(), action func()) {
	t.Helper()
	returned := make(chan struct{})
	go func() { action(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		release()
		<-returned
		t.Fatal("import UI waited for a background discovery operation")
	}
}

func TestRelayImportDoesNotWaitForDiscoveryStartup(t *testing.T) {
	a, b, release := asyncDiscoveryApp(t, nil)
	importUIAction(t, release, a.openRelayImport)
	select {
	case <-b.entered:
	case <-time.After(time.Second):
		t.Fatal("discovery startup was not requested")
	}
	a.lanDisc.mu.Lock()
	a.lanDisc.pending = &discovery.Snapshot{Generation: 1}
	a.lanDisc.mu.Unlock()
	// Check the next frame too: moving Start off-thread is insufficient if
	// rendering immediately waits for Browser.Snapshot or a network query.
	importUIAction(t, release, func() { ui.NewTester(a.view, 1120, 800).Texts() })
	if !a.relayImport.open || !a.lanDisc.ui.starting {
		t.Fatal("the dialog did not open while startup was pending")
	}
	release()
	waitLANBrowse(t, a)
}

func TestRelayImportCloseDuringStartupDiscardsLateResult(t *testing.T) {
	for _, startupErr := range []error{nil, errors.New("stale startup error")} {
		name := "success"
		if startupErr != nil {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			a, b, release := asyncDiscoveryApp(t, startupErr)
			a.openRelayImport()
			<-b.entered
			importUIAction(t, release, a.closeRelayImport)
			release()
			a.lanDisc.wg.Wait()
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.live || a.relayImport.open || a.lanDisc.ui.open || a.lanDisc.ui.err != "" || a.lanDisc.browseResult != nil {
				t.Fatal("closed import retained a late startup result or live browser")
			}
		})
	}
}

func TestRelayImportReopenDuringStartupUsesNewestRequest(t *testing.T) {
	a, b, release := asyncDiscoveryApp(t, errors.New("stale startup error"))
	a.openRelayImport()
	<-b.entered
	a.closeRelayImport()
	cacheImportInterfaces(a.lanDisc)
	a.openRelayImport()
	a.setLANDiscoveryInterface("Wi-Fi")
	// Even an old snapshot arriving after reopen must wait for the new start.
	a.lanDisc.mu.Lock()
	a.lanDisc.pending = &discovery.Snapshot{Generation: 1, Candidates: []discovery.Candidate{{Name: "old network"}}}
	a.lanDisc.mu.Unlock()
	a.drainLANDiscovery()
	if len(a.lanDisc.ui.cands) != 0 {
		t.Fatal("old network appeared during startup")
	}
	release()
	waitLANBrowse(t, a)
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.starts) != 2 || b.starts[1] != "Wi-Fi" || !b.live || a.lanDisc.ui.err != "" || len(a.lanDisc.ui.cands) != 0 || a.lanDisc.ui.generation != 2 {
		t.Fatalf("latest request was not applied: starts=%v ui=%+v", b.starts, a.lanDisc.ui)
	}
}

func TestRelayImportWithoutLANDoesNotStartComponent(t *testing.T) {
	a, b, release := asyncDiscoveryApp(t, nil)
	a.lanDisc.mu.Lock()
	for i := range a.lanDisc.localCands {
		a.lanDisc.localCands[i].lanSize = false
	}
	a.lanDisc.mu.Unlock()
	release()
	a.openRelayImport()
	waitLANBrowse(t, a)
	a.lanDisc.wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.starts) != 0 || a.relayImport.tab != 1 || a.lanDisc.ui.open {
		t.Fatal("paste-only import launched discovery or did not switch tabs")
	}
}

func TestRelayImportShutdownDuringStartupDoesNotRestart(t *testing.T) {
	a, b, release := asyncDiscoveryApp(t, nil)
	a.openRelayImport()
	<-b.entered
	stopped := make(chan struct{})
	go func() { a.shutdownLANDiscovery(); close(stopped) }()
	waitCondition(t, "discovery shutdown requested", a.lanDiscoveryShutDown)
	release()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("startup worker did not finish on shutdown")
	}
	a.closeRelayImport()
	a.openRelayImport()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live || len(b.starts) != 1 || a.lanDisc.ui.open {
		t.Fatal("late page action restarted discovery after shutdown")
	}
}

func TestRelayImportRefreshAndCloseDoNotWait(t *testing.T) {
	a, b, release := asyncDiscoveryApp(t, nil)
	a.openRelayImport()
	release()
	waitLANBrowse(t, a)
	b.refreshEntered, b.refreshRelease = make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(b.refreshRelease) }) }
	defer finish()
	importUIAction(t, finish, a.refreshLANDiscovery)
	<-b.refreshEntered
	importUIAction(t, finish, a.closeRelayImport)
	finish()
	a.lanDisc.wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live {
		t.Fatal("refresh kept browsing alive after close")
	}
}

func TestRelayImportRenderingUsesCachedInterfacesAfterExpiry(t *testing.T) {
	a, _, release := asyncDiscoveryApp(t, nil)
	a.openRelayImport()
	release()
	waitLANBrowse(t, a)
	a.lanDisc.mu.Lock()
	a.lanDisc.localAt = time.Now().Add(-time.Minute)
	a.lanDisc.localAddrs = []relay.Interface{{Name: "LAN", IPv4: "192.168.1.2"}}
	a.lanDisc.mu.Unlock()
	labels, _ := a.discoveryInterfaceChoices()
	addresses := a.localLANCandidates()
	if len(labels) != 2 || labels[0] != "LAN" || labels[1] != "Wi-Fi" || len(addresses) != 1 || addresses[0].Name != "LAN" {
		t.Fatal("rendering re-enumerated interfaces after cache expiry")
	}
}

func TestRelayImportStartupFailureDoesNotRestoreOldCandidates(t *testing.T) {
	a, b, release := asyncDiscoveryApp(t, errors.New("component startup failed"))
	b.candidates = []discovery.Candidate{{Name: "previous network"}}
	a.openRelayImport()
	release()
	waitLANBrowse(t, a)
	if a.lanDisc.ui.err == "" || len(a.lanDisc.ui.cands) != 0 {
		t.Fatal("failed startup restored candidates from an older session")
	}
}
