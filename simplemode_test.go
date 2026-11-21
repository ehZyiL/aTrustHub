package main

// 简单模式（M1）的验收用例：一个接入点、一个网址输入框、其余概念收进设置。
// 这些用例先写好，实现按它们来。
//
// 三条护栏也在这里钉住：
//   1. 简单模式只裁展示与默认值，不改任何业务逻辑（接管档位仍然按平台/配置隐藏）；
//   2. 一定要留显式退出（设置页「显示全部设置」）；
//   3. 日志与诊断入口不能消失（失败列表和设置页的日志分区都还在）。

import (
	"slices"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// onePointApp 造一个只有一个接入点的应用：简单模式的前提。
func onePointApp(t *testing.T, p model.AccessPoint) *app {
	t.Helper()
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Points = []model.AccessPoint{p}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.mgr.Apply(a.cfg)
	return a
}

// simpleApp 是「一个 aTrust 接入点 + 简单模式」的标准场景。
func simpleApp(t *testing.T) *app {
	t.Helper()
	a := onePointApp(t, model.AccessPoint{
		ID: "P1", Name: "公司主网关", Server: "atrust.corp.example", Port: 443,
		Username: "alice", AuthMode: string(model.AuthModePassword),
		Protocol: model.ProtocolATrust,
	})
	a.setSimpleMode(true)
	return a
}

// frames 渲染一帧并返回所有可见文本。
func frames(t *testing.T, a *app, w, h int) (string, *ui.Tester) {
	t.Helper()
	tt := ui.NewTester(a.view, w, h)
	tt.Frame()
	return strings.Join(tt.Texts(), "|"), tt
}

// 默认不是简单模式；用户选了之后 Normalize 不能把它清掉。
func TestSimpleModeDefaults(t *testing.T) {
	s := model.DefaultSettings()
	if s.SimpleMode {
		t.Error("首次运行不该默认进简单模式：它要由用户显式选择")
	}
	s.SimpleMode = true
	s.Normalize()
	if !s.SimpleMode {
		t.Error("Normalize 不该清掉用户选中的简单模式")
	}
	var zero model.Settings
	zero.Normalize()
	if zero.SimpleMode {
		t.Error("空设置应当归到默认值（非简单模式）")
	}
	if zero.AggregatePort != 1080 {
		t.Errorf("空设置应当归到默认端口，实际 %d", zero.AggregatePort)
	}
}

// 简单模式的概念收敛：一个代理地址、没有独立端口，且可重复调用。
func TestConvergeSimple(t *testing.T) {
	cfg := model.Config{
		Settings: model.Settings{
			ListenHost: "127.0.0.1", AggregatePort: 1080,
			Routing: model.RoutingLatency, AggregateEnabled: false,
		},
		Points: []model.AccessPoint{
			{ID: "A", Name: "A", SocksPort: 10001, InPool: false},
			{ID: "B", Name: "B", SocksPort: 10002, InPool: true},
		},
	}
	cfg.ConvergeSimple()
	for _, p := range cfg.Points {
		if p.SocksPort != 0 {
			t.Errorf("%s 的独立 SOCKS5 端口应当归零，实际 %d", p.Name, p.SocksPort)
		}
		if !p.InPool {
			t.Errorf("%s 应当加入统一入口：简单模式下只有一个代理地址", p.Name)
		}
	}
	if !cfg.Settings.AggregateEnabled {
		t.Error("简单模式必须保留统一入口，它是唯一的代理地址")
	}
	again := cfg.Points[0].SocksPort
	cfg.ConvergeSimple()
	if cfg.Points[0].SocksPort != again {
		t.Error("ConvergeSimple 应当可重复调用（幂等）")
	}
	// 退出简单模式：独立端口要补回来，否则等于悄悄吞掉用户的配置。
	cfg.Settings.SimpleMode = false
	cfg.RestorePorts()
	if cfg.Points[0].SocksPort == 0 || cfg.Points[1].SocksPort == 0 {
		t.Errorf("退出简单模式应当补回独立端口，实际 %d / %d",
			cfg.Points[0].SocksPort, cfg.Points[1].SocksPort)
	}
	if cfg.Points[0].SocksPort == cfg.Points[1].SocksPort {
		t.Error("两个接入点不该分到同一个端口")
	}
}

// 顶栏在简单模式下只剩两段；逻辑 tab 仍是 0 和 3，不改 a.tab 的含义。
func TestPageNavSimpleMode(t *testing.T) {
	a := testApp(t)
	if got := pageNavLabels(a); len(got) != 4 || got[0] != "接入点" {
		t.Fatalf("完整模式的导航应当是四段，实际 %v", got)
	}
	if pages := a.pages(); len(pages) != 4 || pages[3].Tab != 3 {
		t.Fatalf("完整模式的页面应当是 0..3，实际 %+v", pages)
	}
	a.setSimpleMode(true)
	if got, want := pageNavLabels(a), []string{"连接", "内网网站"}; !slices.Equal(got, want) {
		t.Fatalf("简单模式的导航应当是 %v，实际 %v", want, got)
	}
	pages := a.pages()
	if len(pages) != 2 || pages[0].Tab != 0 || pages[1].Tab != 3 {
		t.Fatalf("简单模式的页面应当是 0 与 3，实际 %+v", pages)
	}
}

// 首屏：一张卡 + 接管方式 + 网址输入框 + 高级设置入口；多网关那一套不出现。
func TestSimpleHomeLayout(t *testing.T) {
	a := simpleApp(t)
	texts, _ := frames(t, a, 1120, 780)
	for _, want := range []string{"连接", "公司主网关", "网络接管", "打开内网网站", "内网地址", "高级设置"} {
		if !strings.Contains(texts, want) {
			t.Errorf("首屏缺少 %q；texts = %s", want, texts)
		}
	}
	for _, no := range []string{"全部接入点重新登录", "常用入口", "本机软件", "网关资源", "独立 SOCKS5", "运行环境"} {
		if strings.Contains(texts, no) {
			t.Errorf("简单模式首屏不该出现 %q；texts = %s", no, texts)
		}
	}
	// 护栏 3：统一入口地址还在首屏（系统代理这一档要用它）。
	if !strings.Contains(texts, "统一入口") && !strings.Contains(texts, "入口未启动") {
		t.Errorf("首屏应当仍然能看到入口状态；texts = %s", texts)
	}
}

// 简单模式但不止一个接入点时退回列表：单卡只描述唯一那个，多个点会看不清。
func TestSimpleHomeFallsBackToMulti(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Points = []model.AccessPoint{
			{ID: "P1", Name: "公司主网关", Server: "atrust.corp.example", Port: 443, Username: "a", AuthMode: string(model.AuthModePassword)},
			{ID: "P2", Name: "办公网线路", Server: "ec.corp.example", Port: 443, Username: "b", AuthMode: string(model.AuthModePassword), Protocol: model.ProtocolEasyConnect},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.mgr.Apply(a.cfg)
	a.setSimpleMode(true)
	texts, _ := frames(t, a, 1120, 780)
	if !strings.Contains(texts, "公司主网关") || !strings.Contains(texts, "办公网线路") {
		t.Errorf("多个接入点时应当都列出来；texts = %s", texts)
	}
	if strings.Contains(texts, "打开内网网站") {
		t.Errorf("多个接入点时不该用单卡；texts = %s", texts)
	}
}

// 打开 / 关闭简单模式都要把 tab 收敛到存在的页面上。
func TestSimpleModeClampsTab(t *testing.T) {
	a := testApp(t)
	a.tab = 2
	a.setSimpleMode(true)
	if a.tab != 0 {
		t.Errorf("简单模式下没有「访问日志」页，tab 应当收敛到 0，实际 %d", a.tab)
	}
	a.tab = 3
	a.setSimpleMode(true)
	if a.tab != 3 {
		t.Errorf("「内网网站」在简单模式下合法，tab 应当保持 3，实际 %d", a.tab)
	}
	a.setSimpleMode(false)
	if a.tab != 3 {
		t.Errorf("关掉简单模式不该动当前 tab，实际 %d", a.tab)
	}
}

// 选择要落盘：下次启动还是简单模式；关掉也要落盘。
func TestSimpleModePersists(t *testing.T) {
	a := testApp(t)
	if a.simpleMode() {
		t.Fatal("默认不该是简单模式")
	}
	a.setSimpleMode(true)
	if !a.store.Config().Settings.SimpleMode {
		t.Error("简单模式没有写进配置")
	}
	if !a.cfg.Settings.SimpleMode {
		t.Error("内存里的配置也要跟着变，否则界面要等重启")
	}
	a.setSimpleMode(false)
	if a.store.Config().Settings.SimpleMode {
		t.Error("关掉简单模式也要落盘")
	}
	if a.cfg.Settings.SimpleMode {
		t.Error("关掉之后内存里的配置应当同步")
	}
}

// 网址输入归一化：空的不开，缺协议的补 https。
func TestSiteTarget(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", false},
		{"   ", "", false},
		{"oa.corp.example", "https://oa.corp.example", true},
		{" https://oa.corp.example/x ", "https://oa.corp.example/x", true},
		{"http://10.1.1.5:8080", "http://10.1.1.5:8080", true},
		{"10.1.1.5:8080", "https://10.1.1.5:8080", true},
	}
	for _, c := range cases {
		got, ok := siteTarget(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("siteTarget(%q) = %q,%v，期望 %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// 网址磁贴：网关下发的可打开应用 + 本机保存的浏览器项目，按地址去重，别的点不算。
func TestSimpleSiteTiles(t *testing.T) {
	a := onePointApp(t, model.AccessPoint{ID: "A", Name: "A", Server: "a.example", Port: 443})
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.LocalApps = []model.LocalApp{
			{ID: "l1", Name: "OA 门户", PointID: "A", Mode: model.LocalAppBrowser, URL: "https://oa.corp.example"},
			{ID: "l2", Name: "别家的库", PointID: "B", Mode: model.LocalAppTCPForward,
				RemoteAddress: "10.0.0.1:3306", ListenPort: 3306},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	v := vpn.View{ID: "A", State: vpn.StateOnline, Apps: []vpn.App{
		{ID: "app-1", Name: "部门管理系统", AccessEntry: "https://oa.corp.example"},
		{ID: "app-2", Name: "报表系统", AccessEntry: "http://report.corp.example"},
	}}
	tiles := a.simpleSiteTiles(v)
	if len(tiles) != 2 {
		t.Fatalf("应当有 2 个磁贴（同址去重、别的接入点不算），实际 %+v", tiles)
	}
	if tiles[0].URL != "https://oa.corp.example" || tiles[0].Name != "部门管理系统" {
		t.Errorf("网关下发的应用应当排在前面，实际 %+v", tiles[0])
	}
	if tiles[1].URL != "http://report.corp.example" {
		t.Errorf("第二个磁贴应当是报表系统，实际 %+v", tiles[1])
	}
	// 离线时只剩本机保存的网址：没登录也敢让人点进去是很糟的体验。
	offline := a.simpleSiteTiles(vpn.View{ID: "A", State: vpn.StateError})
	if len(offline) != 1 || offline[0].Name != "OA 门户" {
		t.Errorf("离线时应当只保留本机保存的网址，实际 %+v", offline)
	}
}

// 设置页：简单模式下只留常用项，并且给一个「显示全部设置」的出口。
func TestSimpleSettingsHidesAdvanced(t *testing.T) {
	a := simpleApp(t)
	a.openSettingsAt(settingGeneral)
	texts, tt := frames(t, a, 1120, 780)
	for _, want := range []string{"简单模式", "显示全部设置"} {
		if !strings.Contains(texts, want) {
			t.Errorf("简单模式的设置页缺少 %q；texts = %s", want, texts)
		}
	}
	for _, no := range []string{"监听地址", "统一入口端口", "分流模式"} {
		if strings.Contains(texts, no) {
			t.Errorf("简单模式不该露出 %q；texts = %s", no, texts)
		}
	}
	if err := tt.Click("显示全部设置"); err != nil {
		t.Fatalf("点「显示全部设置」失败: %v", err)
	}
	tt.Frame()
	if a.simpleMode() {
		t.Error("「显示全部设置」应当关掉简单模式")
	}
	if texts := strings.Join(tt.Texts(), "|"); !strings.Contains(texts, "监听地址") {
		t.Errorf("关掉之后应当能看到专业设置；texts = %s", texts)
	}
}

// 「内网网站」页：一个输入框 + 磁贴，不出现本机项目的模式/执行文件那一套。
func TestSimpleSitesPage(t *testing.T) {
	a := simpleApp(t)
	a.tab = 3
	texts, _ := frames(t, a, 1120, 780)
	for _, want := range []string{"内网网站", "内网地址", "用代理浏览器打开"} {
		if !strings.Contains(texts, want) {
			t.Errorf("网站页缺少 %q；texts = %s", want, texts)
		}
	}
	for _, no := range []string{"＋ 添加项目", "搜索本机项目", "软件 TCP 接管"} {
		if strings.Contains(texts, no) {
			t.Errorf("简单模式的网站页不该出现 %q；texts = %s", no, texts)
		}
	}
}

// 首屏在最小窗口里也不能越界：简单模式主打的是「一眼看完」，
// 溢出等于把关键按钮裁掉。
func TestSimpleHomeFitsNarrowWindow(t *testing.T) {
	a := simpleApp(t)
	for _, size := range []struct{ w, h int }{{880, 560}, {1120, 780}} {
		tt := ui.NewTester(a.view, size.w, size.h)
		tt.Frame()
		for _, label := range []string{"连接", "公司主网关", "网络接管", "内网地址", "用代理浏览器打开"} {
			r, ok := tt.Find(label)
			if !ok {
				t.Errorf("%dx%d 找不到 %q", size.w, size.h, label)
				continue
			}
			if r.X < -0.5 || r.Y < -0.5 ||
				r.X+r.W > float32(size.w)+0.5 || r.Y+r.H > float32(size.h)+0.5 {
				t.Errorf("%dx%d: %q 越出窗口 rect=%+v", size.w, size.h, label, r)
			}
		}
	}
}

// 护栏 1：简单模式不复制接管逻辑。平台/配置做不到的档位照样隐藏。
func TestSimpleHomeKeepsCaptureModes(t *testing.T) {
	if !supportsSystemProxy() {
		t.Skip("本平台没有系统代理这一档")
	}
	a := onePointApp(t, model.AccessPoint{
		ID: "E", Name: "河投商城", Server: "ec.corp.example", Port: 443,
		Username: "alice", AuthMode: string(model.AuthModePassword),
		Protocol: model.ProtocolEasyConnect,
	})
	a.setSimpleMode(true)
	texts, _ := frames(t, a, 1120, 780)
	if !strings.Contains(texts, captureSystem) {
		t.Errorf("首屏应当能切系统代理；texts = %s", texts)
	}
	if strings.Contains(texts, captureGlobalTUN) {
		t.Errorf("只有 EasyConnect 接入点时不该出现全局 TUN；texts = %s", texts)
	}
}
