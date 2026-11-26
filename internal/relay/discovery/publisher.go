package discovery

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DefaultRetry is the backoff after a failed registration. It stops early
// instead of retrying forever: the panel shows "发现不可用" and the share keeps
// running, which is the contract for a discovery failure.
var DefaultRetry = []time.Duration{
	time.Second,
	2 * time.Second,
	5 * time.Second,
	10 * time.Second,
	30 * time.Second,
}

// registrationResult is the backend's answer to one Advertise call.
type registrationResult struct {
	reg Registration
	err error
}

// abandonBudget bounds how long the worker waits for a registration it has
// already cancelled. The multicast backend opens its socket with a handful of
// syscalls, and no platform can interrupt those; without a budget a backend that
// never answers would block the coordinator forever and Close could only give up
// on it.
var abandonBudget = 2 * time.Second

// awaitAbandoned collects a cancelled attempt within budget. If the backend
// returns later, the producer retains ownership and closes the registration.
func awaitAbandoned(resCh <-chan registrationResult, abandoned chan struct{}) registrationResult {
	select {
	case res := <-resCh:
		return res
	case <-time.After(abandonBudget):
		close(abandoned)
		return registrationResult{err: errors.New("发现后端未在预算内响应")}
	}
}

// Publisher keeps one announcement alive and follows the share. It is driven by
// state notifications, never by the render loop: a page that was never opened
// cannot make the lifecycle wrong.
//
// The coordination rules are the ones the firewall queue needed: a single
// mutex-protected wanted-state, a single worker, and a wake-up channel that is
// never lost. A registration that finishes for a generation that is no longer
// wanted is closed immediately instead of being published.
type Publisher struct {
	backend  Backend
	logf     func(string, ...any)
	now      func() time.Time
	retry    []time.Duration
	onChange func(Status)

	mu      sync.Mutex
	want    *Announcement
	wantSeq uint64
	status  Status
	reg     Registration
	// published is the announcement the live registration belongs to, and
	// pubGen is its share generation; together they let a repeat notification
	// skip re-registering.
	published *Announcement
	pubGen    uint64
	closed    bool
	// retryPending is true while the worker waits out a backoff. retrySeq ties
	// it to the wanted state it failed for, so a new state retries at once
	// instead of sleeping.
	retryPending bool
	retrySeq     uint64
	// lastFailure suppresses repeating the same error line on every retry.
	lastFailure string

	ctx    context.Context
	cancel context.CancelFunc
	kick   chan struct{}
	done   chan struct{}
}

// PublisherOptions wires the publisher to a backend and to the panel.
type PublisherOptions struct {
	Backend  Backend
	Logf     func(string, ...any)
	Now      func() time.Time
	Retry    []time.Duration
	OnChange func(Status)
}

// NewPublisher prepares a publisher. Set starts its worker, Clear lets it exit
// after withdrawal, and Close prevents all future starts.
func NewPublisher(opts PublisherOptions) *Publisher {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if len(opts.Retry) == 0 {
		opts.Retry = DefaultRetry
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Publisher{
		backend:  opts.Backend,
		logf:     opts.Logf,
		now:      opts.Now,
		retry:    opts.Retry,
		onChange: opts.OnChange,
		status:   Status{State: StatusIdle},
		ctx:      ctx,
		cancel:   cancel,
		kick:     make(chan struct{}, 1),
	}
	return p
}

// Set asks for one announcement. Only the newest one is ever published, and
// re-asserting the announcement that is already wanted is a no-op: otherwise the
// periodic state notification would restart the retry backoff on every tick and
// turn a permanent failure into a request every two seconds.
func (p *Publisher) Set(a Announcement) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if p.want != nil && sameAnnouncement(*p.want, a) {
		p.mu.Unlock()
		return
	}
	p.want = &a
	p.wantSeq++
	if p.done == nil {
		p.done = make(chan struct{})
		go p.loop(p.done)
	}
	p.wake()
	p.mu.Unlock()
}

// Clear withdraws the announcement. Business sharing is untouched.
func (p *Publisher) Clear() {
	p.mu.Lock()
	if p.closed || p.want == nil {
		p.mu.Unlock()
		return
	}
	p.want = nil
	p.wantSeq++
	p.mu.Unlock()
	p.wake()
}

// Status reports what the panel shows. "Published" only claims that this host
// registered, never that a colleague received it.
func (p *Publisher) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Close withdraws the announcement and waits for the worker within budget.
func (p *Publisher) Close(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	p.want = nil
	p.wantSeq++
	done := p.done
	p.mu.Unlock()
	if done == nil {
		p.cancel()
		return nil
	}
	p.wake()

	select {
	case <-done:
	case <-ctx.Done():
		p.cancel()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
		return ctx.Err()
	}
	p.cancel()
	return nil
}

func (p *Publisher) wake() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func (p *Publisher) setStatus(s Status) {
	p.mu.Lock()
	changed := p.status.State != s.State || p.status.Message != s.Message
	p.status = s
	cb := p.onChange
	p.mu.Unlock()
	if changed && cb != nil {
		cb(s)
	}
}

func (p *Publisher) loop(done chan struct{}) {
	defer close(done)
	// The worker owns this context so a Close can cut a slow registration.
	workCtx, workCancel := context.WithCancel(p.ctx)
	defer workCancel()

	var (
		retryTimer *time.Timer
		failures   int
	)
	stopTimer := func() {
		if retryTimer != nil {
			retryTimer.Stop()
			retryTimer = nil
		}
	}
	defer stopTimer()

	for {
		// Wait for something to do — unless the state already differs from what
		// is published. A wake-up consumed while a registration was in flight
		// must not leave the worker blocked with work pending.
		if p.workPending() {
			// Acting now; drop a wake-up that referred to the state we are
			// about to handle. One that arrives later is a genuine change and
			// will supersede the attempt in flight.
			select {
			case <-p.kick:
			default:
			}
		} else {
			var timerC <-chan time.Time
			if retryTimer != nil {
				timerC = retryTimer.C
			}
			select {
			case <-workCtx.Done():
				p.dropRegistration()
				return
			case <-p.kick:
			case <-timerC:
				stopTimer()
			}
			if retryTimer != nil {
				// A state change cancels a pending retry: register now instead
				// of waiting out the backoff.
				stopTimer()
			}
		}

		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			p.dropRegistration()
			return
		}
		p.retryPending = false
		want, seq, current := p.want, p.wantSeq, p.reg
		p.mu.Unlock()

		if want == nil {
			stopTimer()
			failures = 0
			p.dropRegistration()
			p.setStatus(Status{State: StatusIdle})
			p.mu.Lock()
			if p.want == nil {
				p.done = nil
				p.lastFailure = ""
				p.mu.Unlock()
				return
			}
			p.mu.Unlock()
			continue
		}
		if current != nil && p.publishedSame(*want) {
			p.setStatus(Status{State: StatusPublished, Generation: want.Generation})
			continue
		}
		// A different announcement: withdraw the old one first. There is never
		// a moment with two live registrations for the same share.
		if current != nil {
			p.dropRegistration()
		}
		p.setStatus(Status{State: StatusPending, Generation: want.Generation})

		ann := *want
		resCh := make(chan registrationResult)
		abandoned := make(chan struct{})
		attemptCtx, attemptCancel := context.WithCancel(workCtx)
		go func() {
			reg, err := p.backend.Advertise(attemptCtx, ann)
			select {
			case resCh <- registrationResult{reg: reg, err: err}:
			case <-abandoned:
				if reg != nil {
					_ = reg.Close()
				}
			}
		}()

		var res registrationResult
		superseded := false
	wait:
		for {
			select {
			case res = <-resCh:
				break wait
			case <-p.kick:
				// The wanted state changed while registering: abandon this
				// attempt instead of publishing a stale generation.
				superseded = true
				attemptCancel()
				res = awaitAbandoned(resCh, abandoned)
				break wait
			case <-workCtx.Done():
				superseded = true
				attemptCancel()
				res = awaitAbandoned(resCh, abandoned)
				break wait
			}
		}
		attemptCancel()

		if superseded || p.changedSince(seq) {
			if res.reg != nil {
				// The registration arrived after it stopped being wanted.
				_ = res.reg.Close()
			}
			continue
		}
		if res.err != nil {
			if res.reg != nil {
				_ = res.reg.Close()
			}
			failures++
			wait := p.retry[len(p.retry)-1]
			if failures <= len(p.retry) {
				wait = p.retry[failures-1]
			}
			stopTimer()
			retryTimer = time.NewTimer(wait)
			p.mu.Lock()
			p.retryPending = true
			p.retrySeq = seq
			p.mu.Unlock()
			p.setStatus(Status{
				State:      StatusFailed,
				Message:    res.err.Error(),
				RetryAt:    p.now().Add(wait),
				Generation: ann.Generation,
			})
			p.mu.Lock()
			repeated := p.lastFailure == res.err.Error()
			p.lastFailure = res.err.Error()
			p.mu.Unlock()
			if !repeated {
				p.logf("发布失败：%v", res.err)
			}
			continue
		}
		if res.reg == nil {
			// A backend that reports success without a handle would look
			// published while nothing is announced.
			res.err = errors.New("发现后端未返回注册句柄")
			failures++
			wait := p.retry[len(p.retry)-1]
			if failures <= len(p.retry) {
				wait = p.retry[failures-1]
			}
			stopTimer()
			retryTimer = time.NewTimer(wait)
			p.mu.Lock()
			p.retryPending = true
			p.retrySeq = seq
			p.mu.Unlock()
			p.setStatus(Status{State: StatusFailed, Message: res.err.Error(),
				RetryAt: p.now().Add(wait), Generation: ann.Generation})
			continue
		}
		failures = 0
		stopTimer()
		p.mu.Lock()
		p.lastFailure = ""
		p.reg = res.reg
		p.pubGen = ann.Generation
		p.published = &ann
		p.mu.Unlock()
		p.setStatus(Status{State: StatusPublished, Generation: ann.Generation})
	}
}

// dropRegistration withdraws whatever is live.
func (p *Publisher) dropRegistration() {
	p.mu.Lock()
	reg := p.reg
	p.reg = nil
	p.published = nil
	p.pubGen = 0
	p.mu.Unlock()
	if reg != nil {
		if err := reg.Close(); err != nil {
			p.logf("撤销公告失败：%v", err)
		}
	}
}

// workPending reports whether the published state still differs from the wanted
// one. It is the condition that keeps the worker from sleeping through a change
// that arrived while it was busy.
func (p *Publisher) workPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return true
	}
	if p.want == nil {
		return true // withdraw and retire, even if Clear beat the first attempt
	}
	if p.retryPending && p.retrySeq == p.wantSeq {
		// The backoff is the current plan; the kick that would cancel it has
		// already been accounted for by the caller.
		return false
	}
	return p.published == nil || !sameAnnouncement(*p.published, *p.want)
}

func (p *Publisher) changedSince(seq uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.wantSeq != seq || p.closed
}

func (p *Publisher) publishedSame(a Announcement) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.published != nil && sameAnnouncement(*p.published, a)
}

func sameAnnouncement(a, b Announcement) bool {
	return a.ShareID == b.ShareID && a.Name == b.Name && a.Port == b.Port &&
		a.Address == b.Address && a.Interface.Name == b.Interface.Name &&
		a.Interface.IPv4 == b.Interface.IPv4 &&
		a.ProtocolVersion == b.ProtocolVersion && a.Generation == b.Generation
}
