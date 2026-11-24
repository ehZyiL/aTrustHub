package relay

import (
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
}

// clientRegistry enforces the active-client limit and the lease.
type clientRegistry struct {
	mu      sync.Mutex
	byToken map[string]*client
	byID    map[string]*client
	max     int
	lease   time.Duration
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
	defer r.mu.Unlock()
	r.expireLocked(now)
	if old := r.byID[id]; old != nil {
		return nil, errReauth
	}
	if len(r.byToken) >= r.max {
		return nil, NewError(CodeBusy, "分享主机已达到客户端上限")
	}
	c := &client{id: id, name: name, token: token, created: now, expires: now.Add(r.lease)}
	r.byToken[token] = c
	r.byID[id] = c
	return c, nil
}

// errReauth says the instance id already has a live lease.
var errReauth = NewError(CodeBusy, "该客户端实例已连接，请复用当前会话")

// replace swaps an existing instance's lease for a fresh one, which is what a
// bounded re-authentication does. The old token stops working immediately.
func (r *clientRegistry) replace(id, name, token string, now time.Time) *client {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.byID[id]; old != nil {
		delete(r.byToken, old.token)
	}
	c := &client{id: id, name: name, token: token, created: now, expires: now.Add(r.lease)}
	r.byToken[token] = c
	r.byID[id] = c
	return c
}

// lookup returns the live client of a token, or nil.
func (r *clientRegistry) lookup(token string, now time.Time) *client {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.byToken[token]
	if c == nil {
		return nil
	}
	if now.After(c.expires) {
		delete(r.byToken, c.token)
		delete(r.byID, c.id)
		return nil
	}
	return c
}

// touch renews the lease and reports the remaining seconds.
func (r *clientRegistry) touch(c *client, now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	c.expires = now.Add(r.lease)
	return int(r.lease.Seconds())
}

// remove revokes one client.
func (r *clientRegistry) remove(token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.byToken[token]; c != nil {
		delete(r.byToken, c.token)
		delete(r.byID, c.id)
	}
}

// removeAll revokes every client, which is what switching a share off does.
func (r *clientRegistry) removeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byToken = map[string]*client{}
	r.byID = map[string]*client{}
}

// count returns the number of live clients.
func (r *clientRegistry) count(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)
	return len(r.byToken)
}

// expireLocked drops leases that ran out.
func (r *clientRegistry) expireLocked(now time.Time) {
	for token, c := range r.byToken {
		if now.After(c.expires) {
			delete(r.byToken, token)
			delete(r.byID, c.id)
		}
	}
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
			r.expireLocked(now)
			r.mu.Unlock()
		}
	}
}

// connEntry is one accepted tunnel: the downstream connection plus whatever
// upstream was opened for it. Stop must be able to close both without holding
// the registry lock while handlers unwind.
type connEntry struct {
	token string
	mu    sync.Mutex
	conns []net.Conn
}

func (e *connEntry) attach(conn net.Conn) {
	if conn == nil {
		return
	}
	e.mu.Lock()
	e.conns = append(e.conns, conn)
	e.mu.Unlock()
}

func (e *connEntry) close() {
	e.mu.Lock()
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()
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

// acquire reserves a business slot. After stop it refuses, which is what makes
// registration and revocation mutually exclusive.
func (t *connTable) acquire(token string) (*connEntry, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return nil, NewError(CodeShareClosed, "分享已关闭")
	}
	if t.total >= t.maxTotal || t.perClient[token] >= t.maxEach {
		return nil, NewError(CodeBusy, "分享主机的并发连接已满")
	}
	e := &connEntry{token: token}
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
	if !take(r.global, r.rate/60, r.burst, now) {
		return false
	}
	b := r.perIP[ip]
	if b == nil {
		b = &bucket{tokens: r.perBurst, last: now}
		r.perIP[ip] = b
		if len(r.perIP) > 4096 {
			// Bound the map: drop stale sources rather than grow forever.
			for key, old := range r.perIP {
				if now.Sub(old.last) > 10*time.Minute {
					delete(r.perIP, key)
				}
			}
		}
	}
	return take(b, r.perRate/60, r.perBurst, now)
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
