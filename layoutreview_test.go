package main

import (
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
)

// layoutApp 造一个带两个接入点和三个本机项目的应用，供布局检查使用。
func layoutApp(t *testing.T) *app {
	t.Helper()
	a := testApp(t)
	var ids []string
	if _, err := a.store.Update(func(cfg *model.Config) error {
		for _, p := range []model.AccessPoint{
			{Name: "公司主网关", Server: "atrust.corp.example", Port: 443, Username: "alice", AuthMode: string(model.AuthModePassword), InPool: true},
			{Name: "办公网线路", Server: "ec.corp.example", Port: 443, Username: "bob", AuthMode: string(model.AuthModePassword), InPool: true},
			{Name: "浙江大学网关", Server: "vpn.zju.edu.cn", Port: 443, Protocol: model.ProtocolEasyConnect, AuthMode: string(model.AuthModePassword)},
		} {
			ids = append(ids, cfg.Add(p).ID)
		}
		cfg.LocalApps = append(cfg.LocalApps,
			model.LocalApp{ID: model.NewID(), Name: "生产报表数据库", PointID: ids[0], Mode: model.LocalAppTCPForward, RemoteAddress: "10.200.15.88:3306", ListenPort: 3306},
			model.LocalApp{ID: model.NewID(), Name: "OA 协同审批门户", PointID: ids[0], Mode: model.LocalAppBrowser, URL: "https://oa.corp.example"},
			model.LocalApp{ID: model.NewID(), Name: "内网 GitLab", PointID: ids[1], Mode: model.LocalAppBrowser, URL: "https://gitlab.corp"},
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.mgr.Apply(a.cfg)
	for _, id := range ids {
		if err := a.store.SetPassword(id, "pw"); err != nil {
			t.Fatal(err)
		}
	}
	a.mgr.Connect(ids[0])
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if online, _, _ := a.mgr.Counts(); online >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.sysProxyOn = true
	return a
}

// 每个页面在常见窗口尺寸下，关键元素都必须落在窗口内：越界就是被裁掉，
// 这正是“布局不规范”最容易漏掉的一种。
func TestLayoutBoundsWithinWindow(t *testing.T) {
	a := layoutApp(t)
	labels := map[int][]string{
		0: {"接入点", "全部接入点重新登录", "统一入口", "＋ 添加接入点"},
		1: {"网关资源", "搜索资源", "过滤资源", "网络授权与路由"},
		2: {"访问日志", "复制全部", "清空"},
		3: {"本机软件", "搜索本机项目", "＋ 添加项目", "公司主网关", "办公网线路"},
	}
	sizes := []struct{ w, h int }{{1120, 780}, {880, 560}, {1440, 900}}
	for _, size := range sizes {
		for tab, want := range labels {
			a.tab = tab
			tt := ui.NewTester(a.view, size.w, size.h)
			tt.Frame()
			for _, label := range want {
				r, ok := tt.Find(label)
				if !ok {
					t.Errorf("%dx%d tab %d: 找不到 %q", size.w, size.h, tab, label)
					continue
				}
				if r.X < -0.5 || r.Y < -0.5 ||
					r.X+r.W > float32(size.w)+0.5 || r.Y+r.H > float32(size.h)+0.5 {
					t.Errorf("%dx%d tab %d: %q 越出窗口 rect=%+v", size.w, size.h, tab, label, r)
				}
			}
			// 搜索框是固定宽度控件，窗口变窄也不该被挤细，否则输入区就不堪用了。
			if tab == 3 {
				if r, ok := tt.Find("搜索本机项目"); ok && r.W < 220 {
					t.Errorf("%dx%d: 搜索框被挤到 %.1f（应 ≥220）", size.w, size.h, r.W)
				}
			}
		}
	}
}

// 设置页是整页多 tab：每个分区的关键控件都必须在窗口内。
func TestSettingsPageFitsWindow(t *testing.T) {
	a := layoutApp(t)
	sections := map[int][]string{
		settingGeneral: {"设置", "监听地址", "统一入口端口", "分流模式"},
		settingNetwork: {"网络与接管", "接管方式", "当前接管：系统代理"},
		settingLogs:    {"日志", "运行日志", "打开 TUN 日志"},
		settingAbout:   {"关于", "版本", "项目主页", "打开数据目录"},
	}
	for _, size := range []struct{ w, h int }{{1120, 780}, {880, 560}} {
		for section, want := range sections {
			a.settings.open = false
			a.openSettingsAt(section)
			tt := ui.NewTester(a.view, size.w, size.h)
			tt.Frame()
			for _, label := range want {
				r, ok := tt.Find(label)
				if !ok {
					t.Errorf("%dx%d 设置分区 %d: 找不到 %q", size.w, size.h, section, label)
					continue
				}
				if r.X < -0.5 || r.Y < -0.5 ||
					r.X+r.W > float32(size.w)+0.5 || r.Y+r.H > float32(size.h)+0.5 {
					t.Errorf("%dx%d 设置分区 %d: %q 越出窗口 rect=%+v", size.w, size.h, section, label, r)
				}
			}
		}
	}
}

// 弹窗在最小窗口下也要完整：标题在上、页脚按钮在下，且都落在窗口内。
func TestDialogFitsWindow(t *testing.T) {
	a := layoutApp(t)
	a.tab = 3
	a.openLocalAppEditor(a.cfg.LocalApps[0].ID)
	tt := ui.NewTester(a.view, 880, 560)
	tt.Frame()
	title, ok := tt.Find("编辑本机项目")
	if !ok {
		t.Fatalf("弹窗标题缺失；texts = %v", tt.Texts())
	}
	for _, label := range []string{"保存本机项目", "取消本机项目", "删除项目"} {
		r, ok := tt.Find(label)
		if !ok {
			t.Errorf("页脚按钮 %q 缺失", label)
			continue
		}
		if r.Y+r.H > float32(560) {
			t.Errorf("页脚按钮 %q 越出窗口：%+v", label, r)
		}
		if r.Y <= title.Y {
			t.Errorf("页脚按钮 %q 没有排到标题下方：%+v title=%+v", label, r, title)
		}
	}
	if a.localEditor.err != "" {
		t.Fatalf("打开编辑器失败：%s", a.localEditor.err)
	}
}

// 点行应当直接进编辑器；点行内的启动按钮不应顺带打开编辑器。
func TestLocalAppRowClickOpensEditor(t *testing.T) {
	a := layoutApp(t)
	a.tab = 3
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click("生产报表数据库"); err != nil {
		t.Fatalf("点击项目行：%v", err)
	}
	tt.Frame()
	if !a.localEditor.open || a.localEditor.id == "" {
		t.Fatalf("点行没有打开编辑器：open=%v id=%q", a.localEditor.open, a.localEditor.id)
	}
	a.localEditor.open = false

	tt2 := ui.NewTester(a.view, 1120, 780)
	tt2.Frame()
	if err := tt2.Click("启动 OA 协同审批门户"); err != nil {
		t.Fatalf("点击行内启动：%v", err)
	}
	tt2.Frame()
	if a.localEditor.open {
		t.Fatalf("点行内启动按钮不应打开编辑器")
	}
}

// 分组头点击折叠的行为在两处页面一致：资源分组与项目分组都要能收起、能展开。
func TestGroupHeadersToggle(t *testing.T) {
	a := layoutApp(t)
	for _, tc := range []struct {
		tab    int
		header string
		inside string
	}{
		{1, "公司主网关", "部门管理系统"},
		{3, "办公网线路", "内网 GitLab"},
	} {
		a.tab = tc.tab
		tt := ui.NewTester(a.view, 1120, 780)
		tt.Frame()
		if !tt.HasText(tc.inside) {
			t.Fatalf("tab %d: 展开状态缺少 %q", tc.tab, tc.inside)
		}
		if err := tt.Click(tc.header); err != nil {
			t.Fatalf("tab %d: 点击分组头 %q: %v", tc.tab, tc.header, err)
		}
		tt.Frame()
		if tt.HasText(tc.inside) {
			t.Errorf("tab %d: 收起后仍显示 %q", tc.tab, tc.inside)
		}
		if err := tt.Click(tc.header); err != nil {
			t.Fatalf("tab %d: 再次点击分组头 %q: %v", tc.tab, tc.header, err)
		}
		tt.Frame()
		if !tt.HasText(tc.inside) {
			t.Errorf("tab %d: 展开后缺少 %q", tc.tab, tc.inside)
		}
	}
}
