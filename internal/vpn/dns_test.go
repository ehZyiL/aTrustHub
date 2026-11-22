package vpn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/miekg/dns"
)

func testDNSSession(t *testing.T, mode string) *processSession {
	t.Helper()
	t.Setenv("EASYCONNECT_TEST_WORKER", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sess, err := NewEasyConnectConnector(exe)(ctx, model.AccessPoint{Server: "gateway.invalid", Port: 443}, Credentials{Login: "test-password", Challenge: func(context.Context, Challenge) (string, error) { return "test-code", nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess.(*processSession)
}

func TestWorkerDNSConcurrentRepliesBypassLoginQueue(t *testing.T) {
	s := testDNSSession(t, "dns")
	info := s.Info()
	if info.Resources == nil || info.Resources.Tunnel != "tcp" || len(info.Resources.InternalDomains) != 1 {
		t.Fatal("resource snapshot missing")
	}
	info.Resources.InternalDomains[0] = "changed"
	if s.Info().Resources.InternalDomains[0] != "corp.test" {
		t.Fatal("resource snapshot mutable")
	}
	var wg sync.WaitGroup
	errorsCh := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q := new(dns.Msg).SetQuestion(fmt.Sprintf("name%d.corp.test.", i), dns.TypeAAAA)
			packet, _ := q.Pack()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			answer, err := s.ExchangeDNS(ctx, packet)
			if err != nil {
				errorsCh <- err
				return
			}
			m := new(dns.Msg)
			if m.Unpack(answer) != nil || m.Id != q.Id || m.Question[0] != q.Question[0] || m.Rcode != dns.RcodeNameError {
				errorsCh <- errors.New("wrong DNS request/response correlation")
			}
		}(i)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	if len(s.events) != 0 {
		t.Fatal("online RPC polluted login queue")
	}
}

func TestWorkerDNSCancelCloseAndExit(t *testing.T) {
	for _, mode := range []string{"dns-block", "dns-exit"} {
		t.Run(mode, func(t *testing.T) {
			s := testDNSSession(t, mode)
			q, _ := new(dns.Msg).SetQuestion("private.corp.test.", dns.TypeA).Pack()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, err := s.ExchangeDNS(ctx, q)
			if err == nil {
				t.Fatal("unanswered query succeeded")
			}
			if mode == "dns-block" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancel: %v", err)
			}
			s.dnsMu.Lock()
			pending := len(s.dnsPending)
			s.dnsMu.Unlock()
			if pending != 0 {
				t.Fatal("cancelled request retained")
			}
			s.Close()
			if _, err = s.ExchangeDNS(context.Background(), q); err == nil {
				t.Fatal("closed session accepted DNS")
			}
		})
	}
}

type delayedDNSSession struct {
	*fakeSession
	entered, release chan struct{}
}

func (s *delayedDNSSession) ExchangeDNS(ctx context.Context, packet []byte) ([]byte, error) {
	close(s.entered)
	select {
	case <-s.release:
		return packet, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func TestDNSDiagnosticDiscardsResultAfterReconnect(t *testing.T) {
	sess := &delayedDNSSession{fakeSession: newFakeSession("first"), entered: make(chan struct{}), release: make(chan struct{})}
	ep := &endpoint{state: StateOnline, sess: sess, gen: 1}
	m := &Manager{points: map[string]*endpoint{"vpn": ep}}
	done := make(chan error, 1)
	go func() { _, err := m.ExchangeDNS(context.Background(), "vpn", nil); done <- err }()
	<-sess.entered
	m.mu.Lock()
	ep.gen++
	ep.sess = newFakeSession("second")
	m.mu.Unlock()
	close(sess.release)
	if err := <-done; err == nil {
		t.Fatal("stale DNS response returned after reconnect")
	}
}

func TestMappedDNSIPCDoesNotPublishWithoutMatchingAliases(t *testing.T) {
	for _, mode := range []string{"dns-alias", "dns-alias-wrong"} {
		t.Run(mode, func(t *testing.T) {
			s := testDNSSession(t, mode)
			packet, _ := new(dns.Msg).SetQuestion("a.corp.test.", dns.TypeA).Pack()
			result, err := s.ExchangeMappedDNS(context.Background(), packet, "198.19.64.0/20")
			if mode == "dns-alias-wrong" {
				if err == nil || len(result.DNS) > 0 {
					t.Fatal("unmapped synthetic response exposed to the platform")
				}
			} else if err != nil || len(result.DNSAliases) != 1 || result.DNSAliases[0].Original != "10.90.0.9" {
				t.Fatal("mapping metadata lost", err)
			}
		})
	}
}
