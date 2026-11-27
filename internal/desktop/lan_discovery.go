package desktop

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	relayclient "github.com/ehzyil/connect-hub/internal/relay/client"
	relay "github.com/ehzyil/connect-hub/internal/relay/contract"
	discovery "github.com/ehzyil/connect-hub/internal/relay/discovery/contract"
)

// lanDiscovery owns the two sides of 局域网发现: the publisher that follows the
// share lifecycle, and the browser that only lives while the page is open.
//
// Nothing here runs on the render loop for correctness: the publisher is woken
// by controller notifications through kick, and the browser is started and
// stopped by the UI thread because it is a user action.
type lanDiscovery struct {
	pub     relayclient.Publisher
	browser relayclient.Browser

	wg          sync.WaitGroup
	syncMu      sync.Mutex
	syncPending bool // guarded by mu; notifications coalesce into one worker
	syncRunning bool
	searchStop  chan struct{}
	searchDone  chan struct{}

	// suppressed stops announcements for this run without touching the
	// preference. It is used when the user turns discovery off and the saved
	// preference could not be written: the network stops now, the disk catches
	// up later.
	mu         sync.Mutex
	suppressed bool
	// suppressedGen ties the suppression to the share instance it was made for:
	// a new enable is a new decision and must not inherit it.
	suppressedGen uint64
	shutDown      bool
	// frameWanted is the background-readable copy of "the open page is still
	// searching", so the coordinator never touches UI-thread fields.
	frameWanted bool
	browsing    bool
	// localAddrs caches this machine's LAN addresses. Enumerating interfaces is
	// a syscall per address, and the page renders per frame.
	localAddrs []relay.Interface
	// localCands is localAddrs annotated the way the share panel annotates its
	// own picker (subnet, LAN-sized, virtual), cached on the same clock so the
	// discovery page never re-enumerates interfaces per frame.
	localCands []lanCandidate
	localAt    time.Time
	pending    *discovery.Snapshot
	lastErr    string

	// ui is UI-thread only.
	ui lanDiscoveryUI
}

// lanDiscoveryUI is the 发现局域网分享 page state. It holds no credential: a
// candidate is an address and a name, never an authorization.
type lanDiscoveryUI struct {
	open      bool
	ifaceName string
	err       string
	snap      discovery.Snapshot
	cands     []discovery.Candidate
	// searching is true during the first seconds of a browse: an empty list
	// then means "still looking", not "there is nothing".
	searching bool
	startedAt time.Time
	// searchWindow is how long an empty list reads as "still looking". It is a
	// variable so tests can shorten it.
	searchWindow time.Duration
}

// resumeLANDiscovery runs after the share restored: a share that is already
// running re-announces itself, a waiting one stays quiet.
func (a *app) resumeLANDiscovery() {
	a.kickLANDiscovery()
}

// shutdownLANDiscovery withdraws the announcement before the listener closes,
// then stops browsing. It never blocks quitting for long: a lost goodbye only
// costs colleagues the TTL.
func (a *app) shutdownLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	d.mu.Lock()
	d.shutDown = true
	d.browsing = false
	d.pending = nil
	d.stopSearchLocked()
	d.mu.Unlock()
	d.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = d.pub.Close(ctx)
	cancel()
	_ = d.browser.Shutdown()
}

func (a *app) kickLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.shutDown {
		return
	}
	d.syncPending = true
	if !d.syncRunning {
		d.syncRunning = true
		d.wg.Add(1)
		go a.runLANDiscoverySync(d)
	}
}

// A burst of notifications needs one short-lived worker, not a permanent ticker.
func (a *app) runLANDiscoverySync(d *lanDiscovery) {
	defer d.wg.Done()
	for {
		d.mu.Lock()
		if d.shutDown || !d.syncPending {
			d.syncRunning = false
			d.mu.Unlock()
			return
		}
		d.syncPending = false
		d.mu.Unlock()
		a.syncLANDiscovery()
	}
}

// syncLANDiscovery publishes exactly the announcement the controller allows, or
// nothing. It is the only place that decides, so the state matrix has one
// implementation.
func (a *app) syncLANDiscovery() {
	d := a.lanDisc
	if d == nil || a.lanShare == nil {
		return
	}
	d.syncMu.Lock()
	defer d.syncMu.Unlock()
	generation := a.lanShare.View().Operation
	d.mu.Lock()
	if d.shutDown {
		d.mu.Unlock()
		return
	}
	suppressed := d.suppressed
	stale := suppressed && d.suppressedGen != 0 && d.suppressedGen != generation
	if stale {
		// The share instance changed since the user stopped discovery: the
		// suppression belonged to the old one.
		d.suppressed = false
		suppressed = false
	}
	d.mu.Unlock()
	if suppressed {
		d.pub.Clear()
		return
	}
	view, ok := a.lanShare.DiscoverySnapshot()
	if !ok {
		d.pub.Clear()
		return
	}
	name := view.Name
	if strings.TrimSpace(name) == "" {
		name = model.DefaultDiscoveryName(view.ShareID)
	}
	ann := discovery.Announcement{
		Generation:      view.Generation,
		ShareID:         view.ShareID,
		Name:            name,
		ProtocolVersion: view.ProtocolVersion,
		Interface: discovery.Interface{
			Name: view.InterfaceName,
			IPv4: view.Address,
		},
		Address: view.Address,
		Port:    view.Port,
	}
	if err := ann.Validate(); err != nil {
		// A share that cannot be described correctly is not announced at all.
		a.tunLogf("局域网发现：公告不可用：%v", err)
		d.pub.Clear()
		return
	}
	d.pub.Set(ann)
}

// discoveryStatus is what the host panel shows.
func (a *app) discoveryStatus() discovery.Status {
	if a.lanDisc == nil {
		return discovery.Status{State: discovery.StatusIdle}
	}
	return a.lanDisc.pub.Status()
}

// setLANDiscoveryPreference is the host switch. Turning discovery on saves the
// preference first and only then announces; turning it off stops the network
// immediately and then saves, so a failed save cannot leave a share broadcasting
// after the user said stop.
func (a *app) setLANDiscoveryPreference(enabled bool, name string) error {
	d := a.lanDisc
	if d == nil || a.lanShare == nil {
		return fmt.Errorf("发现尚未初始化")
	}
	d.syncMu.Lock()
	defer d.syncMu.Unlock()
	name = strings.TrimSpace(name)
	if name != "" {
		if err := model.ValidDiscoveryName(name); err != nil {
			return err
		}
	}
	if enabled {
		if err := a.lanShare.SetDiscovery(true, name); err != nil {
			return err
		}
		d.mu.Lock()
		d.suppressed = false
		d.mu.Unlock()
		a.kickLANDiscovery()
		return nil
	}
	d.mu.Lock()
	d.suppressed = true
	d.suppressedGen = a.lanShare.View().Operation
	d.mu.Unlock()
	d.pub.Clear()
	if err := a.lanShare.SetDiscovery(false, name); err != nil {
		return fmt.Errorf("发现已停止，但偏好未保存：%w", err)
	}
	return nil
}

// retryLANDiscoveryPreference re-attempts the save after a failed switch-off.
func (a *app) retryLANDiscoveryPreference() error {
	d := a.lanDisc
	if d == nil || a.lanShare == nil {
		return fmt.Errorf("发现尚未初始化")
	}
	d.syncMu.Lock()
	defer d.syncMu.Unlock()
	// The retry only re-attempts the write; the public name the user chose
	// must survive it.
	name := a.lanShare.Settings().DiscoveryName
	if err := a.lanShare.SetDiscovery(false, name); err != nil {
		return err
	}
	d.mu.Lock()
	d.suppressed = false
	d.mu.Unlock()
	a.kickLANDiscovery()
	return nil
}

// openLANDiscovery is called by the UI when the discovery tab becomes visible.
func (a *app) openLANDiscovery() {
	d := a.lanDisc
	if d == nil || a.lanDiscoveryShutDown() {
		return
	}
	d.ui.open = true
	a.startLANDiscoveryBrowsing()
}

// closeLANDiscovery stops browsing. A closed page must never keep a socket, a
// timer or a callback alive.
func (a *app) closeLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	d.ui.open = false
	d.ui.searching = false
	d.ui.cands = nil
	d.ui.snap = discovery.Snapshot{}
	d.mu.Lock()
	d.browsing = false
	done := d.stopSearchLocked()
	// A snapshot parked by the closing generation must not survive into the
	// next one; the page that reopens starts from an empty list.
	d.pending = nil
	d.localAddrs, d.localCands = nil, nil
	d.localAt = time.Time{}
	d.mu.Unlock()
	_ = d.browser.Close()
	if done != nil {
		<-done
	}
}

func (a *app) startLANDiscoveryBrowsing() {
	d := a.lanDisc
	if d == nil || a.lanDiscoveryShutDown() {
		return
	}
	ifaces := a.browseInterfaces(d.ui.ifaceName)
	d.ui.err = ""
	d.ui.cands = nil
	d.ui.snap = discovery.Snapshot{}
	d.ui.searching = true
	d.ui.startedAt = time.Now()
	d.mu.Lock()
	if d.shutDown {
		d.mu.Unlock()
		return
	}
	d.stopSearchLocked()
	d.browsing = true
	d.frameWanted = true
	// Clear before starting: the new generation's first snapshot must be the
	// only one this page can apply, otherwise a snapshot parked by the previous
	// generation could be shown as if it belonged to the new network.
	d.pending = nil
	window := d.ui.searchWindow
	if window <= 0 {
		window = 5 * time.Second
	}
	stop, done := make(chan struct{}), make(chan struct{})
	d.searchStop, d.searchDone = stop, done
	d.wg.Add(1)
	go a.runLANDiscoverySearch(d, stop, done, window)
	d.mu.Unlock()
	if err := d.browser.Start(ifaces); err != nil {
		d.ui.err = err.Error()
	}
	a.invalidate()
}

// stopSearchLocked cancels the bounded page deadline without touching sharing.
func (d *lanDiscovery) stopSearchLocked() <-chan struct{} {
	done := d.searchDone
	if d.searchStop != nil {
		close(d.searchStop)
	}
	d.searchStop, d.searchDone = nil, nil
	d.frameWanted = false
	return done
}

func (a *app) runLANDiscoverySearch(d *lanDiscovery, stop <-chan struct{}, done chan struct{}, window time.Duration) {
	defer d.wg.Done()
	defer close(done)
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case <-stop:
		return
	case <-timer.C:
	}
	d.mu.Lock()
	current := !d.shutDown && d.searchStop == stop
	if current {
		d.frameWanted = false
	}
	d.mu.Unlock()
	if current {
		a.invalidateCoalesced()
	}
}

// refreshLANDiscovery re-queries the same generation without losing results.
func (a *app) refreshLANDiscovery() {
	d := a.lanDisc
	if d == nil {
		return
	}
	if err := d.browser.Refresh(); err != nil {
		d.ui.err = err.Error()
	}
	a.invalidate()
}

// setLANDiscoveryInterface switches the browsing network. A new network means a
// new generation: entries from the old interface must not survive it.
func (a *app) setLANDiscoveryInterface(name string) {
	d := a.lanDisc
	if d == nil {
		return
	}
	if d.ui.ifaceName == name {
		return
	}
	d.ui.ifaceName = name
	a.startLANDiscoveryBrowsing()
}

// drainLANDiscovery moves a background snapshot onto the UI thread. It is the
// only writer of the list, which keeps the UI free of locking.
func (a *app) drainLANDiscovery() {
	d := a.lanDisc
	if d == nil || !d.ui.open {
		return
	}
	d.mu.Lock()
	snap := d.pending
	d.pending = nil
	d.mu.Unlock()
	if snap != nil && snap.Generation == d.browser.Snapshot().Generation && snap.Generation >= d.ui.snap.Generation {
		// A snapshot from an older generation must not overwrite a newer list. An
		// equal one may: a refresh re-queries without starting a new generation.
		// startLANDiscoveryBrowsing clears the parked slot, so the comparison is
		// never asked to repair a snapshot from the previous network.
		d.ui.snap = *snap
		d.ui.cands = a.withoutOwnShare(snap.Candidates)
	}
	// The "still looking" flag is time-based, so it is recomputed on every frame
	// instead of only when a snapshot arrives.
	window := d.ui.searchWindow
	if window <= 0 {
		window = 5 * time.Second
	}
	d.ui.searching = len(d.ui.cands) == 0 && time.Since(d.ui.startedAt) < window
	d.mu.Lock()
	d.frameWanted = d.ui.searching
	if !d.ui.searching {
		d.stopSearchLocked()
	}
	d.mu.Unlock()
}

// lanDiscoveryShutDown reports whether the app has already stopped discovery.
// After that point a late page-open must not start browsing again: the sockets
// are gone and nothing would ever close them.
func (a *app) lanDiscoveryShutDown() bool {
	d := a.lanDisc
	if d == nil {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.shutDown
}

// withoutOwnShare drops this machine's own announcement from the list. The test
// is address-based on purpose: a bare share ID is self-reported, so filtering on
// the ID alone would hide a real colleague who copied an identity.
func (a *app) withoutOwnShare(cands []discovery.Candidate) []discovery.Candidate {
	if a.lanShare == nil {
		return cands
	}
	own := a.lanShare.Settings()
	if !own.Enabled || own.ShareID == "" {
		return cands
	}
	local := make(map[string]bool)
	for _, cand := range a.localLANCandidates() {
		local[cand.IPv4] = true
	}
	out := make([]discovery.Candidate, 0, len(cands))
	for _, cand := range cands {
		if cand.ShareID == own.ShareID && local[cand.Address] {
			continue
		}
		out = append(out, cand)
	}
	return out
}

// lanDiscoveryNeedsFrame reports whether time-based discovery state requires a
// redraw. Only the open page has such state, and only while it is still inside
// the "searching" window; everything else is event-driven.
//
// This is what keeps the feature free for users who never open it: no sockets,
// no timers that paint, and no per-frame work.
func (a *app) lanDiscoveryNeedsFrame() bool {
	d := a.lanDisc
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.frameWanted
}
