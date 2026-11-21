package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
)

// 本机软件页按接入点分组：分组头写清楚“哪个网关 / 什么状态 / 几个项目”，
// 点一下能收起这一组，收起后组里的项目不再占用列表，但右侧预览保留选中项。
func TestLocalAppsGroupedByPoint(t *testing.T) {
	a := testApp(t)
	var mainID, officeID string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		mainID = cfg.Add(model.AccessPoint{Name: "公司主网关", Server: "atrust.corp.example", Port: 443, Username: "alice", AuthMode: string(model.AuthModePassword)}).ID
		officeID = cfg.Add(model.AccessPoint{Name: "办公网线路", Server: "ec.corp.example", Port: 443, Username: "bob", AuthMode: string(model.AuthModePassword)}).ID
		cfg.LocalApps = append(cfg.LocalApps,
			model.LocalApp{ID: model.NewID(), Name: "生产报表数据库", PointID: mainID, Mode: model.LocalAppTCPForward, RemoteAddress: "10.200.15.88:3306", ListenPort: 3306},
			model.LocalApp{ID: model.NewID(), Name: "OA 协同审批门户", PointID: mainID, Mode: model.LocalAppBrowser, URL: "https://oa.corp.example"},
			model.LocalApp{ID: model.NewID(), Name: "内网 GitLab", PointID: officeID, Mode: model.LocalAppBrowser, URL: "https://gitlab.corp"},
			model.LocalApp{ID: model.NewID(), Name: "遗留项目", PointID: "gone", Mode: model.LocalAppBrowser, URL: "https://old.corp"},
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.mgr.Apply(a.cfg)
	a.tab = 3

	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"公司主网关", "2 个项目", "生产报表数据库", "办公网线路", "接入点已删除", "遗留项目"} {
		if !strings.Contains(texts, want) {
			t.Errorf("本机软件列表缺少 %q；texts = %s", want, texts)
		}
	}

	// 点分组头收起“公司主网关”，未选中的 OA 门户应当从列表里消失。
	if err := tt.Click("公司主网关"); err != nil {
		t.Fatalf("点击分组头: %v", err)
	}
	tt.Frame()
	after := strings.Join(tt.Texts(), "|")
	if strings.Contains(after, "OA 协同审批门户") {
		t.Errorf("收起后仍显示组内项目：%s", after)
	}
	if !strings.Contains(after, "遗留项目") {
		t.Errorf("收起一组不应影响其他组：%s", after)
	}

	// 再点一次展开，组内项目回来。
	if err := tt.Click("公司主网关"); err != nil {
		t.Fatalf("再次点击分组头: %v", err)
	}
	tt.Frame()
	if again := strings.Join(tt.Texts(), "|"); !strings.Contains(again, "OA 协同审批门户") {
		t.Errorf("展开后组内项目没有回来：%s", again)
	}

	// 搜索：按名称／地址／接入点过滤，非命中项应当隐藏。
	a.localQuery = "gitlab"
	search := strings.Join(ui.NewTester(a.view, 1120, 780).Texts(), "|")
	if !strings.Contains(search, "内网 GitLab") {
		t.Errorf("搜索 gitlab 应当命中项目：%s", search)
	}
	if strings.Contains(search, "生产报表数据库") {
		t.Errorf("搜索 gitlab 不应显示其他项目：%s", search)
	}

	// 搜索时忽略折起状态：否则命中的项目被折在组里也看不到。
	a.localCollapsed = map[string]bool{mainID: true}
	a.localQuery = "OA 协同"
	inside := strings.Join(ui.NewTester(a.view, 1120, 780).Texts(), "|")
	if !strings.Contains(inside, "OA 协同审批门户") {
		t.Errorf("搜索时应当自动展开命中分组：%s", inside)
	}

	// 没有命中时给一句可执行的提示，而不是一块空白。
	a.localCollapsed = nil
	a.localQuery = "没有任何东西"
	if empty := strings.Join(ui.NewTester(a.view, 1120, 780).Texts(), "|"); !strings.Contains(empty, "没有匹配的项目") {
		t.Errorf("空搜索缺少提示：%s", empty)
	}
}
