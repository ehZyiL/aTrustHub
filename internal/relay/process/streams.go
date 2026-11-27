package process

import (
	"context"
	"net"
	"sync"
)

// streamGroup owns every hijacked connection, which http.Server.Shutdown does
// not own. Retire revokes a resource generation; Close also refuses new work.
type streamGroup struct {
	mu         sync.Mutex
	closed     bool
	pairs      map[net.Conn]net.Conn
	wg         sync.WaitGroup
	generation uint64
}

func newStreamGroup() *streamGroup { return &streamGroup{pairs: make(map[net.Conn]net.Conn)} }

func (s *streamGroup) Bridge(ctx context.Context, left, right net.Conn) {
	s.BridgeVersion(ctx, left, right, s.Version())
}

func (s *streamGroup) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

func (s *streamGroup) BridgeVersion(ctx context.Context, left, right net.Conn, generation uint64) {
	s.mu.Lock()
	if s.closed || len(s.pairs) >= 256 || s.generation != generation {
		s.mu.Unlock()
		_ = left.Close()
		_ = right.Close()
		return
	}
	s.pairs[left] = right
	s.wg.Add(1)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pairs, left)
		s.mu.Unlock()
		s.wg.Done()
	}()
	bridge(ctx, left, right)
}

func (s *streamGroup) Retire() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation++
	for left, right := range s.pairs {
		_ = left.Close()
		_ = right.Close()
	}
}

func (s *streamGroup) Close() {
	s.mu.Lock()
	s.closed = true
	s.generation++
	for left, right := range s.pairs {
		_ = left.Close()
		_ = right.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
