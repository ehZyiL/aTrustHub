package wincapture

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/qy/easyconnect/internal/workeripc"
)

type cleanupTestTransport struct {
	controlTransport
	check func() error
}

func (c *cleanupTestTransport) ConfirmCleanup() error { return c.check() }

func TestSystemStopAfterHelperCrashReleasesPoolOnlyAfterCleanupConfirmed(t *testing.T) {
	p, starts, requests := fakeRuntimePool(t, func(frame) frame { return frame{Type: "ok"} })
	s, release, err := p.acquire(context.Background(), "A/1", poolTestConfig("A"))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ready, checks := false, 0
	s.runtime.file = &cleanupTestTransport{controlTransport: s.runtime.file, check: func() error {
		checks++
		if !ready {
			return errors.New("watchdog cleanup pending")
		}
		return nil
	}}
	stop, err := s.EnableSystem(context.Background(), Upstream{Address: "127.0.0.1:23456", Username: "system", Password: strings.Repeat("s", 64)})
	if err != nil {
		t.Fatal(err)
	}
	nextPoolRequest(t, requests, "system_on", s.id)
	s.runtime.fail(errors.New("helper process exited"))
	if err := stop(); err == nil {
		t.Fatal("unconfirmed crash cleanup reported success")
	}
	ready = true
	if err := stop(); err != nil {
		t.Fatal("confirmed crash cleanup still requires a dead helper response", err)
	}
	if checks != 2 {
		t.Fatalf("cleanup was not verified on each pending retry: %d", checks)
	}
	if err := stop(); err != nil || checks != 2 {
		t.Fatal("completed cleanup was not idempotent", err)
	}
	release()
	if p.runtime != nil || len(p.sessions) != 0 {
		t.Fatal("confirmed cleanup retained the dead runtime")
	}
	_, releaseNew, err := p.acquire(context.Background(), "A/1", poolTestConfig("A"))
	if err != nil {
		t.Fatal("same online VPN cannot start a replacement helper", err)
	}
	defer releaseNew()
	if starts.Load() != 2 {
		t.Fatal("replacement helper was not opened")
	}
}

func TestSystemStopDoesNotAssumeClosedTransportMeansCleanup(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	s := newSession(client)
	s.fail(errors.New("control connection lost"))
	stop, err := s.EnableSystem(context.Background(), Upstream{Address: "127.0.0.1:23456", Username: "system", Password: strings.Repeat("s", 64)})
	if err == nil || stop == nil {
		t.Fatal("failed startup lost its cleanup capability", err)
	}
	if err := stop(); err == nil {
		t.Fatal("closed transport without OS cleanup evidence reported success")
	}
}

func TestSystemStopRetriesNativeFailureUntilAcknowledged(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "startup_rollback"}[failStart], func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			session := newSession(client)
			defer session.fail(nil)
			session.file = &cleanupTestTransport{controlTransport: session.file, check: func() error {
				t.Error("live helper failure must still require its cleanup acknowledgement")
				return nil
			}}
			_ = peer.SetDeadline(time.Now().Add(3 * time.Second))
			result := make(chan error, 1)
			go func() {
				reader := bufio.NewReaderSize(peer, maxFrame)
				for i, command := range []string{"system_on", "system_off", "system_off"} {
					var request frame
					if err := readFrame(reader, &request); err != nil {
						result <- err
						return
					}
					if request.Type != command {
						result <- net.ErrClosed
						return
					}
					reply := frame{Type: "ok"}
					if i == 1 || i == 0 && failStart {
						reply = frame{Type: "error", Error: "native cleanup pending"}
					}
					if err := writeFrame(peer, reply); err != nil {
						result <- err
						return
					}
				}
				result <- nil
			}()
			stop, err := session.EnableSystem(context.Background(), Upstream{Address: "127.0.0.1:23456", Username: "system", Password: strings.Repeat("s", 64)})
			if (err != nil) != failStart || stop == nil {
				t.Fatal("startup lost cleanup capability", err)
			}
			if err := stop(); err == nil {
				t.Fatal("failed removal reported success")
			}
			if err := stop(); err != nil {
				t.Fatal("removal was not retried", err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			// A completed stop must remain successful after transport shutdown.
			session.fail(nil)
			if err := stop(); err != nil {
				t.Fatal("completed stop repeated a request", err)
			}
		})
	}
}

func TestSystemScopeSharesRuntimeWithoutOverridingApplicationBinding(t *testing.T) {
	e, counts := testSessionEngine(t)
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	resource := netip.MustParsePrefix("10.44.0.0/24")
	upstream := Upstream{Address: "127.0.0.1:23456", Username: "system", Password: strings.Repeat("s", 64)}
	for i, id := range []string{a, b} {
		if err := e.registerPrepared(id, poolTestConfig(id), netip.MustParsePrefix([]string{"198.19.0.0/20", "198.19.16.0/20"}[i]), []netip.Prefix{resource}, nil); err != nil {
			t.Fatal(err)
		}
		// The route installer is replaced; mark the prepared transaction ready
		// without invoking the native route inventory in this fixture.
		if err := e.sessions[id].rules.Enable(); err != nil {
			t.Fatal(err)
		}
		if err := e.enableSystem(id, &upstream); err != nil {
			t.Fatal(err)
		}
		if err := e.publish(id, []workeripc.DNSAlias{{Address: e.sessions[id].aliases.Addr().Next().String(), Original: "10.44.0.8", TTL: 60}}); err != nil {
			t.Fatal(err)
		}
	}
	system, err := e.selectSystem(netip.MustParseAddr("198.19.16.1"))
	if err != nil || system == nil || system != e.sessions[a].system {
		t.Fatal("system ingress split", err)
	}
	if err := e.validateAppTarget(a, netip.MustParseAddr("198.19.16.1")); err == nil {
		t.Fatal("system mode overrode A's trusted app binding")
	}
	if err := e.disableSystem(b); err != nil {
		t.Fatal(err)
	}
	if counts[resource] != 1 || e.system != system || system.ctx.Err() != nil {
		t.Fatal("B removal interrupted A runtime")
	}
	if _, err := e.selectSystem(netip.MustParseAddr("198.19.16.1")); err == nil {
		t.Fatal("removed B still authorized mapped system traffic")
	}
	if err := e.disableSystem(a); err != nil {
		t.Fatal(err)
	}
	if counts[resource] != 0 || system.ctx.Err() != context.Canceled {
		t.Fatal("last system scope not cleaned")
	}
}
