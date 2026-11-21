package localapps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/ehZyiL/connect-hub/internal/capture"
	"github.com/ehZyiL/connect-hub/internal/dnsmapping"
	"github.com/ehZyiL/connect-hub/internal/netpolicy"
	"github.com/ehZyiL/connect-hub/internal/workeripc"
)

type fakeSystemLease struct {
	starts, syncs int
	request       capture.SystemConfig
	publish       func(string, []workeripc.DNSAlias) error
	err           error
	closeErr      error
	closes        int
}

func (f *fakeSystemLease) configure(config capture.SystemConfig) (capture.SystemState, error) {
	f.request = config
	state := capture.SystemState{Original: capture.Upstream{Address: "127.0.0.1:12345", Username: "original", Password: strings.Repeat("a", 64)}, Prefixes: map[string]string{}}
	for i, resource := range config.Resources {
		if !resource.Guard && len(resource.Domains) > 0 {
			state.Prefixes[resource.ID] = fmt.Sprintf("198.19.%d.0/20", i*16)
			if resource.RequiredPrefix != "" {
				state.Prefixes[resource.ID] = resource.RequiredPrefix
			}
		}
	}
	return state, f.err
}
func (f *fakeSystemLease) Start(_ context.Context, config capture.SystemConfig) (capture.SystemState, error) {
	f.starts++
	return f.configure(config)
}
func (f *fakeSystemLease) Sync(_ context.Context, config capture.SystemConfig) (capture.SystemState, error) {
	f.syncs++
	return f.configure(config)
}
func (f *fakeSystemLease) Publish(_ context.Context, id string, aliases []workeripc.DNSAlias) error {
	return f.publish(id, aliases)
}
func (f *fakeSystemLease) Ping(context.Context) error { return f.err }
func (f *fakeSystemLease) Close() error               { f.closes++; return f.closeErr }

type transferableAlias struct {
	fakeAliasBinding
	prefix string
	ref    capture.AliasRef
}

func TestLinuxSystemCloseReleasesDNSLeaseWhenHelperCloseFails(t *testing.T) {
	pool := &dnsPool{prepare: func(context.Context, string, CaptureConfig) (aliasBinding, error) {
		return &transferableAlias{fakeAliasBinding: fakeAliasBinding{done: make(chan struct{})}, prefix: "198.19.0.0/20",
			ref: capture.AliasRef{ID: strings.Repeat("a", 32), Token: strings.Repeat("b", 64)}}, nil
	}}
	t.Cleanup(pool.close)
	config := aliasTestConfig("A/1")
	binding, err := pool.acquire(config)
	if err != nil {
		t.Fatal(err)
	}
	closeErr := errors.New("system helper cleanup pending")
	lease := &fakeSystemLease{closeErr: closeErr}
	r := &linuxSystemCapture{lease: lease, bindings: map[string]*dnsBinding{config.Key: binding}, cancel: func() {}, done: make(chan struct{})}
	if err := r.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error=%v, want helper cleanup error", err)
	}
	pool.mu.Lock()
	refs := pool.entries[config.Key].refs
	pool.mu.Unlock()
	if refs != 0 || len(r.bindings) != 0 {
		t.Fatal("helper failure retained the mode reference", refs)
	}
	// A later close can still retry the privileged helper cleanup.
	lease.closeErr = nil
	if err := r.Close(); err != nil || r.lease != nil || lease.closes != 2 {
		t.Fatal("helper cleanup retry was not preserved", lease.closes, err)
	}
}

func (a *transferableAlias) Prefix() string         { return a.prefix }
func (a *transferableAlias) Ref() *capture.AliasRef { return &a.ref }

func TestLinuxSystemAndSoftwareReuseOneGenerationLeaseInEitherOrder(t *testing.T) {
	for _, softwareFirst := range []bool{true, false} {
		t.Run(fmt.Sprint("softwareFirst=", softwareFirst), func(t *testing.T) {
			var active atomic.Bool
			active.Store(true)
			created := 0
			pool := &dnsPool{prepare: func(context.Context, string, CaptureConfig) (aliasBinding, error) {
				created++
				return &transferableAlias{fakeAliasBinding: fakeAliasBinding{done: make(chan struct{})}, prefix: "198.19.0.0/20",
					ref: capture.AliasRef{ID: strings.Repeat("a", 32), Token: strings.Repeat("b", 64)}}, nil
			}}
			t.Cleanup(pool.close)
			config := aliasTestConfig("A/1")
			config.Active, config.Gateway = active.Load, "203.0.113.1"
			config.SelectDNS = func([]byte) (string, func() bool, error) { return config.Key, active.Load, nil }
			config.BeginPublication = func(string) (func(), error) { return func() {}, nil }
			config.ConfirmAliases = func([]workeripc.DNSAlias) error { return nil }
			var software *dnsBinding
			if softwareFirst {
				var err error
				software, err = pool.acquire(config)
				if err != nil {
					t.Fatal(err)
				}
				software.release()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &fakeSystemLease{}
			r := &linuxSystemCapture{lease: f, pool: pool, cancel: cancel, done: make(chan struct{})}
			if err := r.configure(ctx, []CaptureConfig{config}, true); err != nil {
				t.Fatal(err)
			}
			if f.request.Resources[0].Alias == nil || f.request.Resources[0].Alias.Token != strings.Repeat("b", 64) || created != 1 {
				t.Fatal("system did not acquire the existing worker capability")
			}
			if softwareFirst && software.alias != r.bindings[config.Key].alias {
				t.Fatal("system mode created a second mapping identity")
			}
			if err := r.Reconcile(ctx, []CaptureConfig{config}); err != nil || f.syncs != 0 {
				t.Fatal("stable shared lease repeated helper updates", err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			software, err := pool.acquire(config)
			if err != nil || created != 1 {
				t.Fatal("returning to software mode replaced the lease", created, err)
			}
			active.Store(false)
			software.release()
		})
	}
}

func TestLinuxSystemFailedTransferReleasesReferenceButPreservesWorkerLease(t *testing.T) {
	pool := &dnsPool{prepare: func(context.Context, string, CaptureConfig) (aliasBinding, error) {
		return &transferableAlias{fakeAliasBinding: fakeAliasBinding{done: make(chan struct{})}, prefix: "198.19.0.0/20",
			ref: capture.AliasRef{ID: strings.Repeat("a", 32), Token: strings.Repeat("b", 64)}}, nil
	}}
	t.Cleanup(pool.close)
	config := aliasTestConfig("A/1")
	config.Gateway = "203.0.113.1"
	config.SelectDNS = func([]byte) (string, func() bool, error) { return config.Key, config.Active, nil }
	config.BeginPublication = func(string) (func(), error) { return func() {}, nil }
	config.ConfirmAliases = func([]workeripc.DNSAlias) error { return nil }
	f := &fakeSystemLease{err: errors.New("transfer failed")}
	r := &linuxSystemCapture{lease: f, pool: pool}
	if err := r.configure(context.Background(), []CaptureConfig{config}, true); err == nil {
		t.Fatal("transfer failure ignored")
	}
	pool.mu.Lock()
	entry := pool.entries[config.Key]
	refs := entry.refs
	pool.mu.Unlock()
	if refs != 0 || len(r.bindings) != 0 {
		t.Fatal("failed transition retained a mode reference", refs)
	}
	select {
	case <-entry.alias.Done():
		t.Fatal("failed transition destroyed the online worker lease")
	default:
	}
	f.err = nil
	if err := r.configure(context.Background(), []CaptureConfig{config}, true); err != nil || r.bindings[config.Key].alias != entry.alias {
		t.Fatal("retry could not reuse the live capability", err)
	}
	r.bindings[config.Key].release()
}

func TestLinuxSystemReconcileKeepsGuardsAndDoesNotRepeatUnchangedTransactions(t *testing.T) {
	f := &fakeSystemLease{}
	r := &linuxSystemCapture{lease: f}
	config := CaptureConfig{Key: "A/1", Identity: dnsmapping.Identity{GatewayID: "A", Version: "v1"}, Gateway: "vpn.test",
		Networks: []netpolicy.Range{{Min: "10.42.0.1", Max: "10.42.0.9"}}, Active: func() bool { return true }}
	ctx := context.Background()
	if err := r.configure(ctx, []CaptureConfig{config}, true); err != nil {
		t.Fatal(err)
	}

	if err := r.Reconcile(ctx, []CaptureConfig{config}); err != nil || f.starts != 1 || f.syncs != 0 {
		t.Fatal("unchanged transaction repeated", f.starts, f.syncs, err)
	}
	config.Key, config.Guard = "guard/A/1", true
	if err := r.Reconcile(ctx, []CaptureConfig{config}); err != nil || !f.request.Resources[0].Guard || len(r.known) != 1 {
		t.Fatal("offline ownership was not preserved", f.request, err)
	}
	f.err = errors.New("transaction rejected")
	config.Key, config.Guard = "A/2", false
	if err := r.Reconcile(ctx, []CaptureConfig{config}); err == nil || !r.config.Resources[0].Guard {
		t.Fatal("failed transaction replaced current publishers")
	}
}

func TestLinuxSystemRejectsKnownIPv6BeforeUpdatingHelper(t *testing.T) {
	ctx := context.Background()
	lease := &fakeSystemLease{}
	r := &linuxSystemCapture{lease: lease}
	config := CaptureConfig{Key: "A/1", Identity: dnsmapping.Identity{GatewayID: "A", Version: "v1"}, Gateway: "vpn.test",
		Networks: []netpolicy.Range{{Min: "192.0.2.1", Max: "192.0.2.9"}}, Active: func() bool { return true }}
	if err := r.configure(ctx, []CaptureConfig{config}, true); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []*workeripc.ResourceSnapshot{
		{IPRules: []workeripc.IPRule{{Min: "2001:db8::10", Max: "2001:db8::1f"}}},
		{StaticDNS: []workeripc.DNSRecord{{Name: "only-v6.test", Addresses: []string{"2001:db8::20"}}}},
	} {
		ipv6, err := CaptureNetworks(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		online := config
		online.Networks = append(append([]netpolicy.Range(nil), config.Networks...), ipv6...)
		if err := r.Reconcile(ctx, []CaptureConfig{online}); err == nil || !strings.Contains(err.Error(), "IPv6") {
			t.Fatalf("unsupported IPv6 reconcile: %v", err)
		}
		if lease.syncs != 0 || len(lease.request.Resources[0].Networks) != 1 {
			t.Fatalf("unsupported IPv6 changed the active scope: %+v", lease.request.Resources)
		}
	}
}

func TestLinuxSystemDNSPublishesOnlySelectedGenerationAndRequiresAcknowledgement(t *testing.T) {
	f := &fakeSystemLease{}
	r := &linuxSystemCapture{lease: f}
	active := true
	selected := "A/1"
	var events []string
	config := CaptureConfig{Key: selected, Identity: dnsmapping.Identity{GatewayID: "A", Version: "v1"}, Gateway: "vpn.test", Domains: []string{"corp.test"},
		Active:           func() bool { return active },
		SelectDNS:        func([]byte) (string, func() bool, error) { return selected, func() bool { return active }, nil },
		BeginPublication: func(string) (func(), error) { events = append(events, "begin"); return func() {}, nil },
		ConfirmAliases:   func([]workeripc.DNSAlias) error { events = append(events, "confirm"); return nil },
		MappedDNS: func(_ context.Context, packet []byte, prefix string) (workeripc.Message, error) {
			events = append(events, "mapped")
			q := new(dns.Msg)
			_ = q.Unpack(packet)
			m := new(dns.Msg).SetReply(q)
			ip := strings.TrimSuffix(prefix, "0/20") + "1"
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(ip)}}
			wire, err := m.Pack()
			return workeripc.Message{DNS: wire, DNSAliases: []workeripc.DNSAlias{{Address: ip, Original: "10.42.0.8", TTL: 30}}}, err
		}}
	f.publish = func(id string, aliases []workeripc.DNSAlias) error {
		events = append(events, "publish")
		if id != f.request.Resources[0].ID || len(aliases) != 1 {
			t.Fatal("publication changed gateway", id, aliases)
		}
		return f.err
	}
	ctx := context.Background()
	if err := r.configure(ctx, []CaptureConfig{config}, true); err != nil {
		t.Fatal(err)
	}
	packet, _ := new(dns.Msg).SetQuestion("app.corp.test.", dns.TypeA).Pack()
	events = nil
	if answer, err := r.exchange(ctx, packet); err != nil || len(answer) == 0 || strings.Join(events, ",") != "begin,mapped,publish,confirm" {
		t.Fatal("DNS returned before helper acknowledgement", events, err)
	}
	f.err = errors.New("publication failed")
	events = nil
	if _, err := r.exchange(ctx, packet); err == nil || strings.Join(events, ",") != "begin,mapped,publish" {
		t.Fatal("failed publication was confirmed", events, err)
	}
	events = nil
	selected = "B/1"
	if _, err := r.exchange(ctx, packet); err == nil || len(events) != 0 {
		t.Fatal("uninstalled owner fell back to A")
	}
	selected, active = config.Key, false
	if _, err := r.exchange(ctx, packet); err == nil || len(events) != 0 {
		t.Fatal("offline generation published DNS")
	}
}

func TestLinuxSystemDNSSwitchRejectsRebindingBeforeReportingReady(t *testing.T) {
	r := &linuxSystemCapture{lease: &fakeSystemLease{}}
	config := CaptureConfig{Key: "A/1", Gateway: "vpn.test", Domains: []string{"corp.test"}, Active: func() bool { return true },
		SelectDNS:        func([]byte) (string, func() bool, error) { return "A/1", func() bool { return true }, nil },
		MappedDNS:        func(context.Context, []byte, string) (workeripc.Message, error) { return workeripc.Message{}, nil },
		ConfirmAliases:   func([]workeripc.DNSAlias) error { return nil },
		BeginPublication: func(string) (func(), error) { return func() {}, nil },
		CheckPublication: func(string) error { return errors.New("会话映射池不能重新绑定") },
	}
	if err := r.configure(context.Background(), []CaptureConfig{config}, true); err == nil || !strings.Contains(err.Error(), "重新登录") || len(r.publish) != 0 {
		t.Fatal("DNS mode switch silently rebound a worker pool", err)
	}
}

func TestLinuxSystemSendsWorkerPoolConstraintBeforeHelperConfiguration(t *testing.T) {
	f := &fakeSystemLease{}
	r := &linuxSystemCapture{lease: f}
	config := CaptureConfig{Key: "A/1", Gateway: "vpn.test", Domains: []string{"corp.test"}, Active: func() bool { return true },
		SelectDNS:        func([]byte) (string, func() bool, error) { return "A/1", func() bool { return true }, nil },
		MappedDNS:        func(context.Context, []byte, string) (workeripc.Message, error) { return workeripc.Message{}, nil },
		ConfirmAliases:   func([]workeripc.DNSAlias) error { return nil },
		BeginPublication: func(string) (func(), error) { return func() {}, nil },
		MappingPrefix:    func() (string, error) { return "198.19.0.0/20", nil },
	}
	if err := r.configure(context.Background(), []CaptureConfig{config}, true); err != nil {
		t.Fatal(err)
	}
	if f.starts != 1 || len(f.request.Resources) != 1 || f.request.Resources[0].RequiredPrefix != "198.19.0.0/20" {
		t.Fatal("worker mapping constraint was not sent before configuration", f.request)
	}
	config.MappingPrefix = func() (string, error) { return "", errors.New("映射身份已变化") }
	if err := r.configure(context.Background(), []CaptureConfig{config}, false); err == nil || f.syncs != 0 {
		t.Fatal("changed mapping identity reached helper configuration", err)
	}
}
