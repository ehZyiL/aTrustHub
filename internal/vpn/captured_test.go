package vpn

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/netpolicy"
	"github.com/qy/easyconnect/internal/workeripc"
)

func TestCapturedUsesStrictOwnershipAndTrustedOriginalEgress(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.1.0.1", Max: "10.1.0.1", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	b.info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.2.0.1", Max: "10.2.0.1", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	var original atomic.Int32
	ctx := WithOriginalDial(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		original.Add(1)
		return nil, errors.New("original fixture")
	})
	if _, err := m.DialCaptured(context.Background(), "tcp", "10.2.0.1:443"); err == nil {
		t.Fatal("public context accepted as captured")
	}
	conn, err := m.DialCaptured(ctx, "tcp", "10.2.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(conn)
	conn.Close()
	if string(data) != "B" || a.strictCalls.Load() != 0 || b.strictCalls.Load() != 1 || original.Load() != 0 {
		t.Fatal("B-only capture escaped owner")
	}
	if _, err := m.DialCaptured(ctx, "tcp", "192.0.2.80:443"); err == nil || original.Load() != 1 {
		t.Fatal("unmanaged did not use trusted original exit")
	}
	m.Disconnect("B")
	if _, err := m.DialCaptured(ctx, "tcp", "10.2.0.1:443"); err == nil || original.Load() != 1 || a.strictCalls.Load() != 0 {
		t.Fatal("offline internal fell back")
	}
	for _, request := range []struct{ network, address string }{{"udp", "10.1.0.1:443"}, {"tcp6", "[2001:db8::1]:443"}, {"tcp", "b.test:443"}} {
		if _, err := m.DialCaptured(ctx, request.network, request.address); err == nil {
			t.Fatal("unsupported capture", request)
		}
	}
}

func TestCapturedMappingsKeepGatewayGenerationAndOriginalDomain(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.info.Resources = &workeripc.ResourceSnapshot{DomainRules: []workeripc.DomainRule{{Domain: "a.test", PortMin: 443, PortMax: 443, Protocol: "tcp"}}}
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	for i, id := range []string{"A", "B"} {
		connection, err := m.LocalAppConnection(id)
		if err != nil {
			t.Fatal(err)
		}
		prefix, address, domain := "198.19.0.0/20", "198.19.0.1", "a.test"
		if i == 1 {
			prefix, address, domain = "198.19.16.0/20", "198.19.16.1", "b.test"
		}
		finish, err := connection.BeginPublication(prefix)
		if err != nil {
			t.Fatal(err)
		}
		defer finish()
		aliases := []workeripc.DNSAlias{{Address: address, Original: "10.0.0.8", TTL: 60}}
		if err := m.mappings.Stage(connection.Key, domain, aliases); err != nil {
			t.Fatal(err)
		}
		if err := connection.ConfirmAliases(aliases); err != nil {
			t.Fatal(err)
		}
	}
	ctx := WithOriginalDial(context.Background(), func(context.Context, string, string) (net.Conn, error) {
		t.Error("mapped direct")
		return nil, net.ErrClosed
	})
	for _, tc := range []struct{ address, want string }{{"198.19.0.1:443", "A"}, {"198.19.16.1:443", "B"}} {
		conn, err := m.DialCaptured(ctx, "tcp", tc.address)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(conn)
		conn.Close()
		if string(data) != tc.want {
			t.Fatal("identical real IP crossed gateways", string(data))
		}
	}
	if _, err := m.DialCaptured(ctx, "tcp", "198.19.0.2:443"); err == nil {
		t.Fatal("unpublished alias accepted")
	}
	m.mu.Lock()
	m.points["B"].gen++
	m.mu.Unlock()
	if _, err := m.DialCaptured(ctx, "tcp", "198.19.16.1:443"); err == nil {
		t.Fatal("old alias rebound to new generation")
	}
}

func TestDeletedGatewayCaptureCannotFallBackToOriginal(t *testing.T) {
	m := routeTestManager(t, model.DefaultSettings())
	var calls atomic.Int32
	ctx := WithOriginalDial(context.Background(), func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, net.ErrClosed })
	ctx = WithCapturedOwnership(ctx, []netpolicy.Range{{Min: "10.44.0.8", Max: "10.44.0.8"}})
	if _, err := m.DialCaptured(ctx, "tcp", "10.44.0.8:443"); err == nil || calls.Load() != 0 {
		t.Fatal("deleted internal owner escaped to original")
	}
	if _, err := m.DialCaptured(ctx, "tcp", "192.0.2.80:443"); err == nil || calls.Load() != 1 {
		t.Fatal("unrelated original traffic blocked")
	}
}

func TestCapturedUDPKeepsOwnerAndGeneration(t *testing.T) {
	a, b := routeTestSession("A"), routeTestSession("B")
	a.udp, b.udp = true, true
	b.info.Resources = &workeripc.ResourceSnapshot{IPRules: []workeripc.IPRule{{Min: "10.2.0.1", Max: "10.2.0.1", PortMin: 9000, PortMax: 9000, Protocol: "udp"}}, DomainRules: []workeripc.DomainRule{{Domain: "short.test", PortMin: 9000, PortMax: 9000, Protocol: "udp"}}}
	m := routeTestManager(t, model.DefaultSettings(), a, b)
	var direct atomic.Int32
	ctx := WithOriginalDial(context.Background(), func(context.Context, string, string) (net.Conn, error) { direct.Add(1); return nil, net.ErrClosed })
	if _, err := m.Dial(context.Background(), "udp", "10.2.0.1:9000"); err == nil {
		t.Fatal("public route opened private UDP")
	}
	for _, target := range []string{"10.2.0.1:9001", "192.0.2.1:9000", "198.19.0.1:9000", "[2001:db8::1]:9000"} {
		if _, err := m.DialCapturedUDP(ctx, target); err == nil {
			t.Fatalf("allowed %s", target)
		}
	}
	b.udp = false
	if _, err := m.DialCapturedUDP(ctx, "10.2.0.1:9000"); err == nil || b.strictCalls.Load() != 0 {
		t.Fatal("tried old worker without UDP support")
	}
	b.udp = true
	conn, err := m.DialCapturedUDP(ctx, "10.2.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var payload [1]byte
	if _, err := io.ReadFull(conn, payload[:]); err != nil || payload[0] != 'B' {
		t.Fatalf("wrong UDP exit %q %v", payload, err)
	}
	events := m.bus.Tail(1)
	if len(events) != 1 || events[0].Route.Actual != "B" || events[0].Route.Stage != "udp_ready" {
		t.Fatalf("unexpected route log: %+v", events)
	}
	owner, err := m.LocalAppConnection("B")
	if err != nil {
		t.Fatal(err)
	}
	finish, err := owner.BeginPublication("198.19.16.0/20")
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	aliases := []workeripc.DNSAlias{{Address: "198.19.16.1", Original: "10.2.0.1", TTL: 60}}
	if err := m.mappings.Stage(owner.Key, "short.test", aliases); err != nil {
		t.Fatal(err)
	}
	if err := owner.ConfirmAliases(aliases); err != nil {
		t.Fatal(err)
	}
	mapped, err := m.DialCapturedUDP(ctx, "198.19.16.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mapped.Close() })
	if _, err := io.ReadFull(mapped, payload[:]); err != nil || payload[0] != 'B' {
		t.Fatalf("mapped UDP crossed gateway %q %v", payload, err)
	}
	m.Disconnect("B")
	if _, err := conn.Write([]byte("old")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("old association usable: %v", err)
	}
	for _, target := range []string{"10.2.0.1:9000", "198.19.16.1:9000"} {
		if _, err := m.DialCapturedUDP(ctx, target); err == nil {
			t.Fatalf("offline UDP allowed for %s", target)
		}
	}
	if a.strictCalls.Load() != 0 || b.strictCalls.Load() != 2 || direct.Load() != 0 {
		t.Fatal("UDP escaped the selected worker")
	}
}
