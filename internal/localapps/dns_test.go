package localapps

import (
	"context"
	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/workeripc"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestDNSDomainsNormalizeWithoutTakingPublicRoot(t *testing.T) {
	result, err := DNSDomains(&workeripc.ResourceSnapshot{InternalDomains: []string{"corp.test", "deep.corp.test"}, DomainRules: []workeripc.DomainRule{{Domain: "*.Other.Test."}}, StaticDNS: []workeripc.DNSRecord{{Name: "host.other.test"}}})
	if err != nil || !reflect.DeepEqual(result, []string{"corp.test", "other.test"}) {
		t.Fatalf("domains=%v %v", result, err)
	}
	for _, bad := range []string{".", "*.com", "public.test\n~.", "foo..test"} {
		if _, err := DNSDomains(&workeripc.ResourceSnapshot{InternalDomains: []string{bad}}); err == nil {
			t.Fatalf("unsafe suffix accepted %q", bad)
		}
	}
}

func TestDNSDomainsGatewayDirtyResourceTolerance(t *testing.T) {
	snap := &workeripc.ResourceSnapshot{
		DomainRules: []workeripc.DomainRule{
			{Domain: "valid.company.com"},
			{Domain: "*.wildcard.company.com"},
			{Domain: "underscore_host.company.com"},
			{Domain: "10.20.30.40"},
			{Domain: "host.withport.com:8443"},
			{Domain: ""},
			{Domain: "*"},
		},
		StaticDNS: []workeripc.DNSRecord{
			{Name: "valid.static.com"},
			{Name: "shortname"},
			{Name: "192.168.1.1"},
			{Name: ""},
		},
	}
	result, err := DNSDomains(snap)
	if err != nil {
		t.Fatalf("unexpected error on dirty gateway resources: %v", err)
	}
	want := []string{"host.withport.com", "valid.company.com", "valid.static.com", "wildcard.company.com"}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("result = %v, want = %v", result, want)
	}
}

func TestDNSFailureStopsCaptureAndReportsReason(t *testing.T) {
	m := NewManager(nil)
	defer m.Close()
	process := &fakeCapture{done: make(chan struct{})}
	m.captureStart = func(context.Context, model.LocalApp, DialFunc) (managedCapture, error) { return process, nil }
	cfg := CaptureConfig{Key: "current-session", Domains: []string{"corp.test"}, Exchange: func(context.Context, []byte) ([]byte, error) { return nil, net.ErrClosed }}
	if err := m.StartCapture(captureProfile(), unusedDial, func() bool { return true }, cfg); err != nil {
		t.Fatal(err)
	}
	awaitView(t, m, func(v View) bool { return v.Running && v.DNSDomains == 1 })
	m.dns.mu.Lock()
	server := m.dns.entries[cfg.Key].server
	m.dns.mu.Unlock()
	server.Close()
	awaitView(t, m, func(v View) bool { return !v.Running && v.Error != "" })
	select {
	case <-process.done:
	default:
		t.Fatal("DNS failure left capture active")
	}
	m.dns.mu.Lock()
	n := len(m.dns.entries)
	m.dns.mu.Unlock()
	if n != 0 {
		t.Fatal("DNS binding leaked after failure")
	}
}

func TestDNSPoolSharedUntilLastCaptureStops(t *testing.T) {
	var pool dnsPool
	config := CaptureConfig{Key: "session-1", Domains: []string{"corp.test"}, Exchange: func(_ context.Context, p []byte) ([]byte, error) {
		q := new(dns.Msg)
		if err := q.Unpack(p); err != nil {
			return nil, err
		}
		return new(dns.Msg).SetRcode(q, dns.RcodeNameError).Pack()
	}}
	one, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	defer one.release()
	two, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	defer two.release()
	if one.address != two.address {
		t.Fatal("same VPN opened competing DNS listeners")
	}
	one.release()
	q := new(dns.Msg).SetQuestion("corp.test.", dns.TypeA)
	if m, _, err := (&dns.Client{Timeout: time.Second}).Exchange(q, two.address); err != nil || m.Rcode != dns.RcodeNameError {
		t.Fatalf("first stop closed shared DNS: %v %v", m, err)
	}
	two.release()
	select {
	case <-two.done:
	default:
		t.Fatal("last stop did not close DNS")
	}
	if c, err := net.DialTimeout("tcp", two.address, time.Second); err == nil {
		c.Close()
		t.Fatal("DNS listener leaked")
	}
	config.Key = "session-2"
	three, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	three.release()
}
