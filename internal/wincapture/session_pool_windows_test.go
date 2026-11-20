package wincapture

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/workeripc"
)

func poolTestConfig(id string) Config {
	return Config{GatewayID: id, Generation: 1, ResourceVersion: "v1", Scope: "application", Gateway: "vpn.test"}
}

func fakeRuntimePool(t *testing.T, respond func(frame) frame) (*runtimePool, *atomic.Int32, <-chan frame) {
	t.Helper()
	var starts atomic.Int32
	requests := make(chan frame, 64)
	p := newSessionPool(func(_ context.Context, _ string, _ Config) (*Session, error) {
		starts.Add(1)
		client, peer := net.Pipe()
		s := newSession(client)
		s.prefix = "198.19.0.0/20"
		t.Cleanup(func() { s.fail(nil); peer.Close() })
		go func() {
			defer peer.Close()
			r := bufio.NewReaderSize(peer, maxFrame)
			for {
				var req frame
				if readFrame(r, &req) != nil {
					return
				}
				requests <- req
				if writeFrame(peer, respond(req)) != nil {
					return
				}
				if req.Type == "close" {
					return
				}
			}
		}()
		return s, nil
	})
	return p, &starts, requests
}

func nextPoolRequest(t *testing.T, requests <-chan frame, command, id string) frame {
	t.Helper()
	select {
	case request := <-requests:
		if request.Type != command || request.Session != id {
			t.Fatalf("request = %s/%s, want %s/%s", request.Type, request.Session, command, id)
		}
		return request
	case <-time.After(time.Second):
		t.Fatal("missing request", command)
	}
	return frame{}
}

func TestPoolMultiplexesGenerationsAndReleaseOnlyRemovesItsSession(t *testing.T) {
	p, starts, requests := fakeRuntimePool(t, func(frame) frame { return frame{Type: "ok", Prefix: "198.19.16.0/20"} })
	a, releaseA, err := p.acquire(context.Background(), "A/1", poolTestConfig("A"))
	if err != nil {
		t.Fatal(err)
	}
	a2, releaseA2, err := p.acquire(context.Background(), "A/1", poolTestConfig("A"))
	if err != nil || a != a2 {
		t.Fatal("same generation did not share lease", err)
	}
	b, releaseB, err := p.acquire(context.Background(), "B/1", poolTestConfig("B"))
	if err != nil {
		t.Fatal(err)
	}
	nextPoolRequest(t, requests, "register", b.id)
	if starts.Load() != 1 || a.runtime != b.runtime || a.Prefix() == b.Prefix() {
		t.Fatal("runtime or pool identity not isolated")
	}
	if err := b.Publish(context.Background(), []workeripc.DNSAlias{{Address: "198.19.16.1", Original: "10.0.0.8", TTL: 60}}); err != nil {
		t.Fatal(err)
	}
	nextPoolRequest(t, requests, "publish", b.id)
	releaseA()
	select {
	case request := <-requests:
		t.Fatal("released another application's reference", request.Type)
	default:
	}
	releaseB()
	releaseB()
	nextPoolRequest(t, requests, "unregister", b.id)
	select {
	case <-a.Done():
		t.Fatal("B removal stopped A")
	default:
	}
	if err := a.Publish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	nextPoolRequest(t, requests, "publish", a.id)
	if err := b.Publish(context.Background(), nil); err == nil {
		t.Fatal("closed B published")
	}
	releaseA2()
	nextPoolRequest(t, requests, "unregister", a.id)
	nextPoolRequest(t, requests, "close", "")
	if p.runtime != nil {
		t.Fatal("last reference leaked helper")
	}
}

func TestCancelledRegistrationRollsBackOnlyNewSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, starts, requests := fakeRuntimePool(t, func(req frame) frame {
		if req.Type == "register" {
			cancel()
		}
		return frame{Type: "ok", Prefix: "198.19.16.0/20"}
	})
	a, releaseA, err := p.acquire(context.Background(), "A/1", poolTestConfig("A"))
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	if _, _, err := p.acquire(ctx, "B/1", poolTestConfig("B")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled registration survived", err)
	}
	request := <-requests
	if request.Type != "register" {
		t.Fatal(request.Type)
	}
	nextPoolRequest(t, requests, "unregister", request.Session)
	if err := a.Publish(context.Background(), nil); err != nil {
		t.Fatal("A lost control channel", err)
	}
	nextPoolRequest(t, requests, "publish", a.id)
	if starts.Load() != 1 || len(p.sessions) != 1 {
		t.Fatal("rollback restarted helper or leaked B")
	}
}

func TestRegistrationFailureAndConfigMutationDoNotAffectExistingSession(t *testing.T) {
	p, _, requests := fakeRuntimePool(t, func(req frame) frame {
		if req.Type == "register" {
			return frame{Type: "error", Error: "new session conflicts"}
		}
		return frame{Type: "ok"}
	})
	config := poolTestConfig("A")
	config.Domains, config.DNSAddress = []string{"a.test"}, "127.0.0.1:23456"
	a, release, err := p.acquire(context.Background(), "A/1", config)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	config.Domains[0] = "changed.test"
	if _, _, err := p.acquire(context.Background(), "A/1", config); err == nil {
		t.Fatal("mutable caller data changed active scope")
	}
	if _, _, err := p.acquire(context.Background(), "B/1", poolTestConfig("B")); err == nil {
		t.Fatal("conflict accepted")
	}
	request := <-requests
	if request.Type != "register" {
		t.Fatal(request.Type)
	}
	if err := a.Publish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}
