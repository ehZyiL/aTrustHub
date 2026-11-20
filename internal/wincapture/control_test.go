package wincapture

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestSharedControlCancellationPreservesOtherApplications(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	session := newSession(client)
	defer session.fail(nil)
	reader := bufio.NewReaderSize(peer, maxFrame)
	_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attached := make(chan error, 1)
	go func() { _, err := session.request(ctx, frame{Type: "attach"}); attached <- err }()
	var request frame
	if err := readFrame(reader, &request); err != nil || request.Type != "attach" {
		t.Fatal(request.Type, err)
	}
	cancel()
	// A second cancelled waiter must leave the in-flight operation alone.
	waiter, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if _, err := session.request(waiter, frame{Type: "publish"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("queued cancellation interfered with the active request", err)
	}
	if err := writeFrame(peer, frame{Type: "ok"}); err != nil {
		t.Fatal("cancelling one launch closed the shared channel", err)
	}
	if err := <-attached; err != nil {
		t.Fatal("attachment acknowledgement was lost instead of allowing detach", err)
	}
	for _, command := range []string{"detach", "ping", "publish"} {
		result := make(chan error, 1)
		go func() { _, err := session.request(context.Background(), frame{Type: command}); result <- err }()
		if err := readFrame(reader, &request); err != nil || request.Type != command {
			t.Fatal("cancelled waiter sent a stray request", request.Type, err)
		}
		if err := writeFrame(peer, frame{Type: "ok"}); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-session.Done():
		t.Fatal("other applications lost their session")
	default:
	}
}

func TestInitialControlCancellationClosesUnsharedSession(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	session := newSession(client)
	defer session.fail(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := session.request(ctx, frame{Type: "configure"}); result <- err }()
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	if err := readFrame(bufio.NewReaderSize(peer, maxFrame), &frame{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled initialization succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("initialization ignored cancellation")
	}
	if !errors.Is(session.Err(), context.Canceled) {
		t.Fatal("cancellation reason lost", session.Err())
	}
}

func TestControlRejectsUnexpectedAcknowledgement(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	session := newSession(client)
	defer session.fail(nil)
	result := make(chan error, 1)
	go func() { _, err := session.request(context.Background(), frame{Type: "ping"}); result <- err }()
	_ = peer.SetDeadline(time.Now().Add(time.Second))
	if err := readFrame(bufio.NewReaderSize(peer, maxFrame), &frame{}); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(peer, frame{Type: "unexpected"}); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("invalid acknowledgement accepted")
	}
	select {
	case <-session.Done():
	default:
		t.Fatal("invalid channel remained reusable")
	}
}
