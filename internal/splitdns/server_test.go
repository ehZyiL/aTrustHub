package splitdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLocalDNSUDPTruncationTCPRetryAndFailure(t *testing.T) {
	s, err := Listen(context.Background(), func(_ context.Context, packet []byte) ([]byte, error) {
		q := new(dns.Msg)
		if err := q.Unpack(packet); err != nil {
			return nil, err
		}
		if q.Question[0].Name == "failure.corp.test." {
			return nil, errors.New("unreachable")
		}
		m := new(dns.Msg).SetReply(q)
		for i := 0; i < 70; i++ {
			r, _ := dns.NewRR(fmt.Sprintf("app.corp.test. 45 IN A 10.0.0.%d", i+1))
			m.Answer = append(m.Answer, r)
		}
		return m.Pack()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q := new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA)
	m, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(q, s.Addr())
	if err != nil || !m.Truncated {
		t.Fatalf("UDP should truncate large answer: %v %v", m, err)
	}
	m, _, err = (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(q, s.Addr())
	if err != nil || m.Truncated || len(m.Answer) != 70 || m.Answer[0].Header().Ttl != 45 {
		t.Fatalf("TCP answer: %v %v", m, err)
	}
	q.SetQuestion("failure.corp.test.", dns.TypeA)
	m, _, err = (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(q, s.Addr())
	if err != nil || m.Rcode != dns.RcodeServerFailure {
		t.Fatalf("upstream failure: %v %v", m, err)
	}
}

func TestLocalDNSDisconnectCancelsQueriesAndClosesPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, exited := make(chan struct{}), make(chan struct{})
	s, err := Listen(ctx, func(ctx context.Context, _ []byte) ([]byte, error) {
		close(entered)
		<-ctx.Done()
		close(exited)
		return nil, ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion("corp.test.", dns.TypeA), s.Addr())
	}()
	<-entered
	cancel()
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("DNS listener survived disconnect")
	}
	select {
	case <-exited:
	default:
		t.Fatal("upstream query not cancelled")
	}
	<-done
	if conn, err := net.DialTimeout("tcp", s.Addr(), time.Second); err == nil {
		conn.Close()
		t.Fatal("DNS listener leaked")
	}
}
