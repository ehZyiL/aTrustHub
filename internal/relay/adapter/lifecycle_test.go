package adapter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/relay"
	session "github.com/ehzyil/connect-hub/internal/vpn/contract"
)

// R1 (cleanup half): fail must still be reaped by the Manager's Close, not
// return early because the session already marked itself closed.
func TestFailedRelaySessionIsStillReaped(t *testing.T) {
	code := relay.ShareCode{Version: 1, Host: "192.168.1.50", Port: 12345, Fingerprint: strings.Repeat("ab", 32)}
	c, err := relay.NewClient(relay.ClientOptions{Code: code})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &relaySession{client: c, done: make(chan struct{}), updates: make(chan session.SessionUpdate, 4), ctx: ctx, cancel: cancel}
	sess.fail(relay.NewError(relay.CodeShareClosed, "closed"))
	// Close after fail must finish cleanup instead of returning early.
	done := make(chan struct{})
	go func() {
		_ = sess.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked after fail")
	}
	select {
	case _, open := <-sess.updates:
		if open {
			t.Fatal("unexpected update after the session ended")
		}
	case <-time.After(time.Second):
		t.Fatal("the update stream was never closed after fail")
	}
}
