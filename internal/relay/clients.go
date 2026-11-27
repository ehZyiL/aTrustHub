package relay

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync"
	"time"
)

// client is one authenticated control session. Its token lives only in this
// process; a restart forces every client to authenticate again.
type client struct {
	id      string
	name    string
	token   string
	created time.Time
	// expires is the lease end, refreshed by status heartbeats. It uses the
	// host's monotonic clock, never a client-supplied time.
	expires time.Time
	// ctx is the lease's lifetime. Revoking the lease cancels it, which aborts
	// that client's pending dials and DNS queries instead of letting them
	// complete after the credential is gone.
	ctx    context.Context
	cancel context.CancelFunc
}

func newClient(id, name, token string, now time.Time, lease time.Duration) *client {
	ctx, cancel := context.WithCancel(context.Background())
	return &client{id: id, name: name, token: token, created: now, expires: now.Add(lease), ctx: ctx, cancel: cancel}
}

// clientRegistry enforces the active-client limit and the lease.
type clientRegistry struct {
	mu      sync.Mutex
	byToken map[string]*client
	byID    map[string]*client
	max     int
	lease   time.Duration
	// onEvict runs after the registry lock is released for every lease that
	// stops being valid, whatever removed it: expiry, an explicit delete, a
	// re-authentication or a shutdown. It must not call back into the registry.
	onEvict func(*client)
}

// revoke runs the eviction hook outside the registry lock.
func (r *clientRegistry) revoke(evicted []*client) {
	if r.onEvict == nil {
		return
	}
	for _, c := range evicted {
		r.onEvict(c)
	}
}

func newClientRegistry(max int, lease time.Duration) *clientRegistry {
	return &clientRegistry{
		byToken: map[string]*client{},
		byID:    map[string]*client{},
		max:     max,
		lease:   lease,
	}
}

// create stores a new client. A re-authentication with the same instance id
// replaces the old lease, so a network retry cannot inflate the client count.
func (r *clientRegistry) create(id, name, token string, now time.Time) (*client, error) {
	r.mu.Lock()
	evicted := r.expireLocked(now)
	if r.byID[id] != nil {
		r.mu.Unlock()
		r.revoke(evicted)
		return nil, errReauth
	}
	if len(r.byToken) >= r.max {
		r.mu.Unlock()
		r.revoke(evicted)
		return nil, NewError(CodeBusy, "分享主机已达到客户端上限")
	}
	c := newClient(id, name, token, now, r.lease)
	r.byToken[token] = c
	r.byID[id] = c
	r.mu.Unlock()
	r.revoke(evicted)
	return c, nil
}

// errReauth says the instance id already has a live lease.
var errReauth = NewError(CodeBusy, "该客户端实例已连接，请复用当前会话")

// replace swaps an existing instance's lease for a fresh one, which is what a
// bounded re-authentication does. The old token stops working immediately.
func (r *clientRegistry) replace(id, name, token string, now time.Time) *client {
	r.mu.Lock()
	var evicted []*client
	if old := r.byID[id]; old != nil {
		evicted = append(evicted, r.evictLocked(old))
	}
	evicted = append(evicted, r.expireLocked(now)...)
	c := newClient(id, name, token, now, r.lease)
	r.byToken[token] = c
	r.byID[id] = c
	r.mu.Unlock()
	r.revoke(evicted)
	return c
}

// lookup returns the live client of a token, or nil. An expired lease is
// revoked here as well, so a request that happens to arrive first still tears
// down the client's tunnels and pending work.
func (r *clientRegistry) lookup(token string, now time.Time) *client {
	r.mu.Lock()
	c := r.byToken[token]
	if c == nil {
		evicted := r.expireLocked(now)
		r.mu.Unlock()
		r.revoke(evicted)
		return nil
	}
	if now.After(c.expires) {
		r.evictLocked(c)
		r.mu.Unlock()
		r.revoke([]*client{c})
		return nil
	}
	r.mu.Unlock()
	return c
}

// touch renews the lease and reports the remaining seconds. Renewal only works
// while the registry still points at this exact lease: a renewal that races with
// expiry or with a replacement must not revive a dead token.
func (r *clientRegistry) touch(c *client, now time.Time) (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byToken[c.token] != c || now.After(c.expires) {
		return 0, false
	}
	c.expires = now.Add(r.lease)
	return int(r.lease.Seconds()), true
}

// remove revokes one client.
func (r *clientRegistry) remove(token string) {
	r.mu.Lock()
	c := r.byToken[token]
	if c != nil {
		r.evictLocked(c)
	}
	r.mu.Unlock()
	if c != nil {
		r.revoke([]*client{c})
	}
}

// removeID revokes the current lease for one authenticated device identity.
func (r *clientRegistry) removeID(id string) {
	r.mu.Lock()
	c := r.byID[id]
	if c != nil {
		r.evictLocked(c)
	}
	r.mu.Unlock()
	if c != nil {
		r.revoke([]*client{c})
	}
}

// removeAll revokes every client, which is what switching a share off does.
func (r *clientRegistry) removeAll() {
	r.mu.Lock()
	evicted := make([]*client, 0, len(r.byToken))
	for _, c := range r.byToken {
		evicted = append(evicted, c)
	}
	r.byToken = map[string]*client{}
	r.byID = map[string]*client{}
	r.mu.Unlock()
	r.revoke(evicted)
}

// count returns the number of live clients. It also revokes whatever it finds
// expired, so asking for the count can never leave dead clients serving.
func (r *clientRegistry) count(now time.Time) int {
	r.mu.Lock()
	evicted := r.expireLocked(now)
	n := len(r.byToken)
	r.mu.Unlock()
	r.revoke(evicted)
	return n
}

// expireLocked drops leases that ran out and returns them for revocation.
func (r *clientRegistry) expireLocked(now time.Time) []*client {
	var evicted []*client
	for _, c := range r.byToken {
		if now.After(c.expires) {
			evicted = append(evicted, r.evictLocked(c))
		}
	}
	return evicted
}

// evictLocked removes one lease from both indexes.
func (r *clientRegistry) evictLocked(c *client) *client {
	delete(r.byToken, c.token)
	delete(r.byID, c.id)
	return c
}

// sweep periodically drops expired leases so an abandoned client stops counting
// even when nothing else touches the registry.
func (r *clientRegistry) sweep(stop <-chan struct{}) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			r.mu.Lock()
			evicted := r.expireLocked(now)
			r.mu.Unlock()
			r.revoke(evicted)
		}
	}
}

// connEntry is one accepted tunnel: the downstream connection plus whatever
// upstream was opened for it. Stop must be able to close both without holding
// the registry lock while handlers unwind.
type connEntry struct {
	token string
	// epoch is the resource generation this tunnel was authorized under. A
	// generation switch retires exactly the entries of older generations.
	epoch uint64
	// ctx is cancelled when the entry is closed, so a dial that is still in
	// flight when its generation is retired is aborted instead of running to
	// completion and being thrown away.
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

// attach registers a connection with the entry. It reports false when the entry
// was already closed, and closes the connection in that case: a dial that
// completes after the generation was retired must never start carrying traffic.
func (e *connEntry) attach(conn net.Conn) bool {
	if conn == nil {
		return true
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		_ = conn.Close()
		return false
	}
	e.conns = append(e.conns, conn)
	e.mu.Unlock()
	return true
}

// close is irreversible: later attaches are refused instead of accepted, and any
// dial still running for this entry is cancelled.
func (e *connEntry) close() {
	e.mu.Lock()
	already := e.closed
	e.closed = true
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
	if already {
		return
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

// connTable is the independent registry HTTP's Shutdown does not provide:
// Server.Shutdown never closes Hijacked connections, so a revocation that only
// closed the listener would leave live tunnels behind.
type connTable struct {
	mu        sync.Mutex
	stopped   bool
	entries   map[*connEntry]struct{}
	perClient map[string]int
	total     int
	maxTotal  int
	maxEach   int
}

func newConnTable(maxTotal, maxEach int) *connTable {
	return &connTable{entries: map[*connEntry]struct{}{}, perClient: map[string]int{}, maxTotal: maxTotal, maxEach: maxEach}
}

// acquire reserves a business slot for one resource generation. After a
// permanent stop it refuses, which is what makes registration and shutdown
// mutually exclusive. A resource change does not stop the table: it retires the
// old generation's entries instead, so authorized requests of the new generation
// can still be accepted.
func (t *connTable) acquire(token string, epoch uint64) (*connEntry, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return nil, NewError(CodeShareClosed, "分享已关闭")
	}
	if t.total >= t.maxTotal || t.perClient[token] >= t.maxEach {
		return nil, NewError(CodeBusy, "分享主机的并发连接已满")
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &connEntry{token: token, epoch: epoch, ctx: ctx, cancel: cancel}
	t.entries[e] = struct{}{}
	t.perClient[token]++
	t.total++
	return e, nil
}

func (t *connTable) release(e *connEntry) {
	if e == nil {
		return
	}
	t.mu.Lock()
	if _, ok := t.entries[e]; ok {
		delete(t.entries, e)
		t.perClient[e.token]--
		if t.perClient[e.token] <= 0 {
			delete(t.perClient, e.token)
		}
		t.total--
	}
	t.mu.Unlock()
	e.close()
}

// retireBefore closes the connections of every generation older than epoch and
// leaves the table open for the new generation. It is the resource-change path,
// as opposed to stopAll's permanent shutdown.
func (t *connTable) retireBefore(epoch uint64) {
	t.mu.Lock()
	var entries []*connEntry
	for e := range t.entries {
		if e.epoch >= epoch {
			continue
		}
		delete(t.entries, e)
		t.perClient[e.token]--
		if t.perClient[e.token] <= 0 {
			delete(t.perClient, e.token)
		}
		t.total--
		entries = append(entries, e)
	}
	t.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
}

// closeAll closes every accepted connection but keeps accepting new ones. It is
// used when a refresh fails: the old authorization may already be gone.
func (t *connTable) closeAll() {
	t.mu.Lock()
	entries := make([]*connEntry, 0, len(t.entries))
	for e := range t.entries {
		entries = append(entries, e)
	}
	t.entries = map[*connEntry]struct{}{}
	t.perClient = map[string]int{}
	t.total = 0
	t.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
}

// stopAll refuses new registrations, then closes every accepted connection
// outside the lock so a handler can still unregister itself.
func (t *connTable) stopAll() {
	t.mu.Lock()
	t.stopped = true
	entries := make([]*connEntry, 0, len(t.entries))
	for e := range t.entries {
		entries = append(entries, e)
	}
	t.entries = map[*connEntry]struct{}{}
	t.perClient = map[string]int{}
	t.total = 0
	t.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
}

// stopClient closes only one client's tunnels, leaving other clients alone.
func (t *connTable) stopClient(token string) {
	t.mu.Lock()
	entries := make([]*connEntry, 0, len(t.entries))
	for e := range t.entries {
		if e.token != token {
			continue
		}
		delete(t.entries, e)
		entries = append(entries, e)
	}
	if n := len(entries); n > 0 {
		t.total -= n
		if t.perClient[token] > n {
			t.perClient[token] -= n
		} else {
			delete(t.perClient, token)
		}
	}
	t.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
}

// count returns the number of accepted business connections.
func (t *connTable) count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.total
}

// rateLimiter is a bounded token bucket per source IP plus a global one. A hit
// returns an error instead of sleeping, so a limited request never occupies a
// handler.
type rateLimiter struct {
	mu       sync.Mutex
	perIP    map[string]*bucket
	global   *bucket
	perRate  float64
	perBurst float64
	rate     float64
	burst    float64
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perIP, perBurst, global, globalBurst float64) *rateLimiter {
	return &rateLimiter{perIP: map[string]*bucket{}, perRate: perIP, perBurst: perBurst, rate: global, burst: globalBurst, now: time.Now}
}

func (r *rateLimiter) allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.global == nil {
		r.global = &bucket{tokens: r.burst, last: now}
	}
	b := r.perIP[ip]
	if b == nil {
		if len(r.perIP) >= 4096 {
			// Bound the map: drop stale sources rather than grow forever.
			for key, old := range r.perIP {
				if now.Sub(old.last) > 10*time.Minute {
					delete(r.perIP, key)
				}
			}
		}
		if len(r.perIP) >= 4096 {
			return false
		}
		b = &bucket{tokens: r.perBurst, last: now}
		r.perIP[ip] = b
	}
	if !take(b, r.perRate/60, r.perBurst, now) {
		return false
	}
	return take(r.global, r.rate/60, r.burst, now)
}

func take(b *bucket, ratePerSecond, burst float64, now time.Time) bool {
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * ratePerSecond
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// tokenDigest is what the server compares for bearer tokens. Comparing digests
// keeps the comparison constant-time without ever handing out the raw secret.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
