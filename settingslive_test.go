package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
)

// 设置页打开时点导航必须能回到页面：点另一页可以，点当前页也可以。
// 这正是「点设置后再点接入点没反应」的回归用例。
func TestNavigationLeavesSettings(t *testing.T) {
	cases := []struct {
		name string
		from int
		tab  string
		want int
	}{
		{"切到另一页", 0, "网关资源", 1},
		{"切回当前页", 0, "接入点", 0},
		{"切到日志页", 0, "访问日志", 2},
		{"切到本机软件", 0, "本机软件", 3},
	}
	for _, c := range cases {
		a := testApp(t)
		a.tab = c.from
		a.openSettings()
		tt := ui.NewTester(a.view, 1120, 780)
		tt.Frame()
		if err := tt.Click(c.tab); err != nil {
			t.Fatalf("%s：点 %q 失败: %v", c.name, c.tab, err)
		}
		tt.Frame()
		if a.settings.open {
			t.Errorf("%s：点 %q 后设置页应当关闭", c.name, c.tab)
		}
		if a.tab != c.want {
			t.Errorf("%s：切页后 tab = %d，想要 %d", c.name, a.tab, c.want)
		}
	}
}

// 设置改成即时生效：页面上没有保存按钮，改一项就落盘。
func TestSettingsApplyWithoutSaveButton(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	if strings.Contains(texts, "保存设置") || strings.Contains(texts, "取消设置") {
		t.Errorf("设置页不该再有保存/取消按钮；texts = %s", texts)
	}
	if !strings.Contains(texts, "改动即时生效") {
		t.Errorf("设置页缺少「改动即时生效」提示；texts = %s", texts)
	}
}

// 改一项就跑一次落盘，而且不关页。
func TestSettingsApplyOnChange(t *testing.T) {
	a := testApp(t)
	a.openSettings()
	a.settings.routing = model.RoutingRoundRobin.Label()
	a.settings.port = "1089"
	a.settings.aggregate = false
	a.applySettingsIfChanged()
	if a.settings.err != "" {
		t.Fatalf("即时应用失败：%s", a.settings.err)
	}
	if !a.settings.open {
		t.Error("即时应用不该关掉设置页")
	}
	cfg := a.store.Config()
	if cfg.Settings.AggregatePort != 1089 || cfg.Settings.Routing != model.RoutingRoundRobin {
		t.Errorf("没有落盘：%+v", cfg.Settings)
	}
	// 再跑一次：草稿与已保存值一致，不该重复写盘（返回 false 即无脏数据）。
	if a.settingsDirty() {
		t.Error("保存后仍认为有未保存改动")
	}
}

// 非法值只提示、不落盘，页面保持打开。
func TestSettingsInvalidValueKeepsDraft(t *testing.T) {
	a := testApp(t)
	before := a.store.Config().Settings.AggregatePort
	a.openSettings()
	a.settings.port = "0"
	a.applySettingsIfChanged()
	if a.settings.err == "" {
		t.Error("端口 0 应当给出错误提示")
	}
	if !a.settings.open {
		t.Error("校验失败不该关设置页")
	}
	if got := a.store.Config().Settings.AggregatePort; got != before {
		t.Errorf("非法端口被写进配置：%d", got)
	}
}
