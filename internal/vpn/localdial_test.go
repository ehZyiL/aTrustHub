package vpn

import (
	"context"
	"io"
	"net"
	"testing"
)

func TestLocalAppDialerStaysWithSessionGeneration(t *testing.T) {
	sess := newFakeSession("first")
	ep := &endpoint{state: StateOnline, sess: sess, gen: 1}
	m := &Manager{points: map[string]*endpoint{"vpn": ep}}
	dial, active, err := m.LocalAppDialer("vpn")
	if err != nil {
		t.Fatal(err)
	}
	c, err := dial(context.Background(), "tcp", "10.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(c)
	c.Close()
	if string(body) != "first" {
		t.Fatal(string(body))
	}
	if !active() {
		t.Fatal("current session is not active")
	}
	ep.state = StateOffline
	if c, err := dial(context.Background(), "tcp", "10.0.0.1:443"); err == nil {
		c.Close()
		t.Fatal("offline lease accepted")
	}
	ep.gen++
	ep.state = StateOnline
	ep.sess = newFakeSession("second")
	if active() {
		t.Fatal("reconnected session kept the old capture active")
	}
	if c, err := dial(context.Background(), "tcp", "10.0.0.1:443"); err == nil {
		c.Close()
		t.Fatal("old lease used a new session")
	}
	if _, _, err := m.LocalAppDialer("missing"); err == nil {
		t.Fatal("missing VPN accepted")
	}
}

type delayedLocalSession struct {
	Session
	started, release chan struct{}
	peer             net.Conn
}

func (s *delayedLocalSession) Dial(context.Context, string, string) (net.Conn, error) {
	a, b := net.Pipe()
	s.peer = b
	close(s.started)
	<-s.release
	return a, nil
}
func TestLocalAppConnectionDiscardsDialAfterSessionReplacement(t *testing.T) {
	s := &delayedLocalSession{Session: newFakeSession("old"), started: make(chan struct{}), release: make(chan struct{})}
	ep := &endpoint{state: StateOnline, sess: s, gen: 1}
	m := &Manager{points: map[string]*endpoint{"vpn": ep}}
	connection, err := m.LocalAppConnection("vpn")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		c, err := connection.Dial(context.Background(), "tcp", "10.0.0.1:443")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	<-s.started
	m.mu.Lock()
	ep.gen++
	ep.sess = newFakeSession("new")
	m.mu.Unlock()
	close(s.release)
	if err := <-done; err == nil {
		t.Fatal("old session result accepted")
	}
	defer s.peer.Close()
	if _, err := s.peer.Write([]byte("late")); err == nil {
		t.Fatal("old connection was not closed")
	}
}
