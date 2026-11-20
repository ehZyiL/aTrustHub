package localapps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/qy/easyconnect/internal/capture"
	"github.com/qy/easyconnect/internal/dnsmapping"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/workeripc"
)

type fakeSystemLease struct {
	starts, syncs int
	request       capture.SystemConfig
	publish       func(string, []workeripc.DNSAlias) error
	err           error
}

func (f *fakeSystemLease) configure(config capture.SystemConfig) (capture.SystemState, error) {
	f.request = config
	state := capture.SystemState{Original: capture.Upstream{Address: "127.0.0.1:12345", Username: "original", Password: strings.Repeat("a", 64)}, Prefixes: map[string]string{}}
	for i, resource := range config.Resources {
		if !resource.Guard && len(resource.Domains) > 0 {
			state.Prefixes[resource.ID] = fmt.Sprintf("198.19.%d.0/20", i*16)
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
func (f *fakeSystemLease) Close() error               { return nil }

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
