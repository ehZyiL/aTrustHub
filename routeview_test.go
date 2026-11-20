package main

import (
	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/store"
	"strings"
	"testing"
)

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
