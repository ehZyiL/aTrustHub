package main

import (
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/store"
	"strings"
	"testing"
)

func TestDNSFailoverGroupUIAndPersistence(t *testing.T) {
	a := testApp(t)
	_, err := a.store.Update(func(cfg *model.Config) error {
		for _, id := range []string{"A", "B"} {
			cfg.Points = append(cfg.Points, model.AccessPoint{ID: id, Name: id})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.openRoutes()
	a.routes.tab = 2
	a.routes.pattern = "corp.test"
	a.routes.dnsFailover = true
	for _, id := range []string{"A", "B"} {
		selected := true
		a.routes.shared[id] = &selected
	}
	a.addRoutePolicy(true)
	if a.routes.err != "" {
		t.Fatal(a.routes.err)
	}
	reloaded, err := store.Open(a.dir, nil)
	if err != nil || len(reloaded.Config().Settings.SharedExits) != 1 || !reloaded.Config().Settings.SharedExits[0].DNSFailover {
		t.Fatal("DNS group flag was not persisted", err)
	}
	texts := strings.Join(ui.NewTester(a.view, 1120, 800).Texts(), "|")
	if !strings.Contains(texts, "DNS 离线备用") {
		t.Fatal(texts)
	}
	a.routes.pattern = "192.0.2.1"
	a.addRoutePolicy(true)
	if a.routes.err == "" || len(a.store.Config().Settings.SharedExits) != 1 {
		t.Fatal("IP-only group accepted DNS equivalence")
	}
}

func TestRoutePolicyUIAndPersistence(t *testing.T) {
	a := testApp(t)
	a.openRoutes()
	tt := ui.NewTester(a.view, 1120, 800)
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "不查询 DNS") {
		t.Fatal(texts)
	}
	a.routes.pattern = "private.example"
	a.routes.action = "阻止"
	a.addRoutePolicy(false)
	if a.routes.err != "" {
		t.Fatal(a.routes.err)
	}
	a.routes.target = "private.example:443"
	a.previewRoute()
	if !strings.Contains(a.routes.result, "用户策略阻止") {
		t.Fatal(a.routes.result)
	}
	reloaded, err := store.Open(a.dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Config().Settings.RoutePolicies) != 1 {
		t.Fatal("policy not persisted")
	}
	a.routes.action = "指定网关"
	a.routes.gateway = "不存在"
	a.addRoutePolicy(false)
	if a.routes.err == "" || len(a.store.Config().Settings.RoutePolicies) != 1 {
		t.Fatal("invalid rule mutated saved config")
	}
	a.routes.tab = 2
	tt = ui.NewTester(a.view, 1120, 800)
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "同业务备用出口") {
		t.Fatal(texts)
	}
}
