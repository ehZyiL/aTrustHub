package discovery

import (
	"context"
	"errors"
	"sync"
	"time"
)

// BrowserOptions wires one browsing UI to a backend.
type BrowserOptions struct {
	Backend Backend
	Logf    func(string, ...any)
	Now     func() time.Time
	// Emit delivers a new immutable snapshot. It is called from a background
	// goroutine; the UI must only hand the value to its own thread.
	Emit func(Snapshot)
}

// Browser owns the browsing side: one session per generation, a bounded cache,
// and snapshots that are safe to hand to the UI thread.
//
// Every start (page opened, network changed, refresh requested) bumps the
// generation. Records that arrive for an older generation are dropped, so a
// stale callback can never revive an entry in a newer list.
type Browser struct {
	backend Backend
	logf    func(string, ...any)
	now     func() time.Time
	emit    func(Snapshot)

	mu       sync.Mutex
	gen      uint64
	session  Session
	cancel   context.CancelFunc
	cache    *cache
	ifaces   []Interface
	started  bool
	err      string
	closed   bool
	shutDown bool

	stopTicker chan struct{}
	tickerDone chan struct{}
	startDone  chan struct{}
}

// NewBrowser creates a browser. Nothing is browsed until Start is called.
func NewBrowser(opts BrowserOptions) *Browser {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Browser{
		backend: opts.Backend,
		logf:    opts.Logf,
		now:     opts.Now,
		emit:    opts.Emit,
		cache:   newCache(opts.Now),
	}
}

// Start begins a new browsing generation on exactly these interfaces. The
// previous generation is closed first and its cache discarded.
func (b *Browser) Start(ifaces []Interface) error {
	b.mu.Lock()
	if b.shutDown {
		b.mu.Unlock()
		return errors.New("发现浏览器已退出")
	}
	// Close ends a browsing session, not the browser: reopening the page must
	// work again (the app closes it whenever the dialog closes).
	b.closed = false
	old := b.session
	oldCancel := b.cancel
	// The expiry loop belongs to the generation that is being torn down, not to
	// the browser: it must stop here, on the success path and on both failure
	// paths, or it would keep expiring a cache that no longer belongs to it.
	oldStop := b.stopTicker
	oldDone := b.tickerDone
	oldStart := b.startDone
	b.gen++
	gen := b.gen
	ctx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})
	b.session = nil
	b.cancel = cancel
	b.startDone = startDone
	b.stopTicker = nil
	b.tickerDone = nil
	b.err = ""
	b.cache.reset()
	b.ifaces = append([]Interface(nil), ifaces...)
	b.started = true
	b.mu.Unlock()
	defer close(startDone)

	if oldCancel != nil {
		oldCancel()
	}
	if oldStop != nil {
		close(oldStop)
		<-oldDone
	}
	if old != nil {
		_ = old.Close()
	}
	if err := waitBrowseStart(oldStart); err != nil {
		cancel()
		b.startFailed(gen, err)
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if len(ifaces) == 0 {
		cancel()
		err := errors.New("没有可用的局域网网卡")
		b.startFailed(gen, err)
		return err
	}

	session, err := b.backend.Browse(ctx, BrowseOptions{
		Interfaces: ifaces,
		Logf:       b.logf,
		OnRecords: func(records []Record) {
			b.apply(gen, records)
		},
	})
	if err != nil {
		cancel()
		if session != nil {
			_ = session.Close()
		}
		b.startFailed(gen, err)
		return err
	}

	b.mu.Lock()
	if b.closed || b.gen != gen {
		// Closed or superseded while the backend was starting. Close already
		// cleared started/err, and a newer generation owns every field, so this
		// attempt has nothing to write: it only releases what it opened.
		b.mu.Unlock()
		cancel()
		_ = session.Close()
		return nil
	}
	b.session = session
	b.cancel = cancel
	b.startTickerLocked()
	b.mu.Unlock()

	b.publish()
	return nil
}

func (b *Browser) startFailed(gen uint64, err error) {
	b.mu.Lock()
	if !b.closed && b.gen == gen {
		b.err = err.Error()
		b.started = false
	}
	b.mu.Unlock()
	b.publish()
}

// Backends normally release Browse as soon as its context is cancelled. A
// stuck platform call must not hold the UI forever; its returning Start still
// owns and closes any late session.
func waitBrowseStart(done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("发现浏览启动未在预算内退出")
	}
}

// Refresh re-queries the current generation without dropping the cache.
func (b *Browser) Refresh() error {
	b.mu.Lock()
	session := b.session
	started := b.started
	b.mu.Unlock()
	if !started || session == nil {
		return errors.New("尚未开始浏览")
	}
	return session.Refresh()
}

// Snapshot returns the current list.
func (b *Browser) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Snapshot{Generation: b.gen, Candidates: b.cache.snapshot()}
}

// Err reports why browsing is not running, if it is not.
func (b *Browser) Err() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

// Close stops browsing and releases every socket.
func (b *Browser) Close() error {
	b.mu.Lock()
	if b.closed {
		done := b.startDone
		b.mu.Unlock()
		return waitBrowseStart(done)
	}
	b.closed = true
	b.gen++
	b.started = false
	b.err = ""
	session := b.session
	cancel := b.cancel
	b.session = nil
	b.cancel = nil
	stop := b.stopTicker
	done := b.tickerDone
	starting := b.startDone
	b.stopTicker = nil
	b.tickerDone = nil
	b.ifaces = nil
	b.cache.reset()
	b.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if stop != nil {
		close(stop)
		<-done
	}
	var err error
	if session != nil {
		err = session.Close()
	}
	return errors.Join(err, waitBrowseStart(starting))
}

// Shutdown is final, unlike closing a page. The check shares Start's mutex so
// a page-open racing with application exit cannot recreate a browsing session.
func (b *Browser) Shutdown() error {
	b.mu.Lock()
	b.shutDown = true
	b.mu.Unlock()
	return b.Close()
}

// apply folds records into the cache, refusing anything from an older
// generation.
func (b *Browser) apply(gen uint64, records []Record) {
	b.mu.Lock()
	current, closed := b.gen, b.closed
	ifaces := b.ifaces
	if gen != current || closed {
		b.mu.Unlock()
		return
	}
	byName := make(map[string]Interface, len(ifaces))
	for _, ifi := range ifaces {
		byName[ifi.Name] = ifi
	}
	changed := false
	for _, rec := range records {
		// An address record names the SRV target host, not the instance, so an
		// empty Instance is expected there.
		if rec.Instance == "" && rec.Host == "" {
			continue
		}
		if rec.Kind == KindA && !rec.Gone() {
			if ifi, ok := byName[rec.Interface]; ok && !ifi.OnLink(rec.IPv4) {
				// Reflected from another subnet: the user cannot reach it from
				// the network they picked, so it is not a candidate.
				continue
			}
		}
		if events := b.cache.apply(rec); len(events) > 0 {
			changed = true
		}
	}
	b.mu.Unlock()
	if changed {
		b.publish()
	}
}

// startTickerLocked installs the expiry timer for the current generation. The
// caller holds b.mu: installing it inside the same critical section that stores
// b.session is what stops a Close that races with a Start from leaving a ticker
// running with nobody left to stop it.
func (b *Browser) startTickerLocked() {
	if b.closed {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	b.stopTicker = stop
	b.tickerDone = done
	go b.expireLoop(stop, done, b.gen)
}

// expireLoop is the single expiry timer of one generation: not one timer per
// candidate, and never a paint request of its own (publish is event-driven).
func (b *Browser) expireLoop(stop <-chan struct{}, done chan struct{}, gen uint64) {
	defer close(done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			b.mu.Lock()
			if b.closed || b.gen != gen {
				b.mu.Unlock()
				return
			}
			changed := len(b.cache.expire()) > 0
			b.mu.Unlock()
			if changed {
				b.publish()
			}
		}
	}
}

func (b *Browser) publish() {
	if b.emit == nil {
		return
	}
	b.mu.Lock()
	gen, closed := b.gen, b.closed
	snapshot := b.cache.snapshot()
	b.mu.Unlock()
	if closed {
		// Nothing may reach the UI after the page closed.
		return
	}
	b.emit(Snapshot{Generation: gen, Candidates: snapshot})
}
