package vpn

import (
	"context"
	"errors"
	"testing"

	"github.com/ehzyil/connect-hub/internal/workeripc"
)

func TestStrictEntryRequiresNegotiatedCapabilities(t *testing.T) {
	for _, m := range []workeripc.Message{
		{Address: "127.0.0.1:12345"},
		{Address: "127.0.0.1:12345", VPNAddress: "127.0.0.1:12346", FlowReporting: true},
	} {
		s := &processSession{}
		if err := s.configureReady(m, "test-only"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DialVPN(context.Background(), "tcp", "b.corp.test:443"); !errors.Is(err, ErrStrictVPNUnavailable) {
			t.Fatalf("strict request downgraded: %v", err)
		}
	}
	for _, mutate := range []func(*workeripc.Message){
		func(m *workeripc.Message) { m.VPNAddress = m.Address },
		func(m *workeripc.Message) { m.VPNAddress = "10.0.0.1:1080" },
		func(m *workeripc.Message) { m.VPNAddress = "127.0.0.1:0" },
		func(m *workeripc.Message) { m.FlowReporting = false },
		func(m *workeripc.Message) { m.Capabilities = []string{"strict_vpn", "flow_cancel"} },
	} {
		m := workeripc.Message{Address: "127.0.0.1:12345", VPNAddress: "127.0.0.1:12346", FlowReporting: true, Capabilities: []string{"strict_vpn", "flow_cancel", "flow_prepare"}}
		mutate(&m)
		if err := (&processSession{}).configureReady(m, "test-only"); !errors.Is(err, ErrStrictVPNUnavailable) {
			t.Fatalf("invalid strict readiness accepted: %v", err)
		}
	}
}

func TestStrictATrustSessionRejectsClosedAndUnsupportedRequests(t *testing.T) {
	s := &zjuSession{}
	if _, err := s.DialVPN(context.Background(), "udp", "10.0.0.1:53"); err == nil {
		t.Fatal("unsupported transport accepted")
	}
	s.closed.Store(true)
	if _, err := s.DialVPN(context.Background(), "tcp", "10.0.0.1:443"); err == nil {
		t.Fatal("closed session accepted")
	}
}
