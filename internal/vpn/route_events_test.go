package vpn

import (
	"context"
	"errors"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/routing"
	"net"
	"strings"
	"testing"
)

func TestPreviewAndDialUsePolicyWithoutPreviewSideEffects(t *testing.T) {
	s := routeTestSession("B")
	settings := model.DefaultSettings()
	settings.RoutePolicies = []routing.Policy{{ID: "selected", Pattern: "b.test", Protocol: "tcp", PortMin: 443, PortMax: 443, Action: "gateway", GatewayID: "B"}}
	m := routeTestManager(t, settings, s)
	m.mu.Lock()
	m.points["B"].cfg.InPool = false
	m.mu.Unlock()
	before := len(m.bus.Tail(0))
	d := m.PreviewRoute(routing.Request{Network: "tcp", Address: "b.test:443"})
	if d.Action != "vpn" || d.RuleID != "selected" || s.strictCalls.Load() != 0 || len(m.bus.Tail(0)) != before {
		t.Fatal(d)
	}
	c, err := m.Dial(context.Background(), "tcp", "b.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	e := m.bus.Tail(1)[0]
	if e.Route == nil || e.Route.Actual != "B" || e.Route.RuleID != d.RuleID || e.Route.Stage != "tcp_established" {
		t.Fatal(e)
	}
	e.Route.Actual = "mutated"
	if m.bus.Tail(1)[0].Route.Actual != "B" {
		t.Fatal("mutable log snapshot")
	}
	s.dial = func(context.Context) (net.Conn, error) { return nil, errors.New("credential=do-not-log") }
	_, _ = m.Dial(context.Background(), "tcp", "b.test:443")
	e = m.bus.Tail(1)[0]
	if strings.Contains(e.Line+e.Route.Detail(), "do-not-log") || e.Route.Actual != "" {
		t.Fatal(e)
	}
}
