package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/model"
	"github.com/ehzyil/connect-hub/internal/vpn"
)

// 底栏只报运行环境：接管方式留在顶栏，同一个东西不该有两个入口。
func TestEnvStripIsRuntimeOnly(t *testing.T) {
	a := layoutApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"统一入口", "本机项目 0 个运行中"} {
		if !strings.Contains(texts, want) {
			t.Errorf("底栏缺少 %q", want)
		}
	}
	if strings.Contains(texts, "助手 已就绪") {
		t.Error("没有检查助手状态时不应显示已就绪")
	}
	// 顶栏的网络状态入口会写一次「接管」，底栏再写一次就算重复。
	if n := strings.Count(texts, "接管"); n > 1 {
		t.Errorf("「接管」出现了 %d 次，底栏不该重复；texts = %s", n, texts)
	}
}

func TestPointCardShowsDiagnosticsAndOpensEditor(t *testing.T) {
	a := layoutApp(t)
	tt := ui.NewTester(a.view, 880, 600)
	tt.Frame()
	_, hasEditButton := tt.Find("编辑 公司主网关")
	if !tt.HasText("HTTP / SOCKS5") || tt.HasText("连接与诊断") || hasEditButton {
		t.Fatal("卡片应直接显示代理信息，且没有诊断或编辑按钮")
	}
	if err := tt.Click("打开常用入口 公司主网关"); err != nil {
		t.Fatal(err)
	}
	if a.editor.open {
		t.Fatal("点击常用入口只应定位卡片")
	}
	tt.Frame()
	name, ok := tt.Find("https://atrust.corp.example · alice@Radius")
	if !ok {
		t.Fatal("找不到接入点卡片名称")
	}
	tt.ClickAt(name.X+name.W/2, name.Y+name.H/2)
	tt.Frame()
	if !a.editor.open || a.editor.editingID != a.cfg.Points[0].ID {
		t.Fatal("点击卡片应该打开对应接入点的编辑器")
	}
	if _, ok := tt.Find("代理浏览器 公司主网关"); !ok {
		t.Fatal("在线接入点的代理浏览器操作应在编辑器中")
	}
}

func TestPointFailureShowsReasonAndLogin(t *testing.T) {
	a := testApp(t)
	v := vpn.View{
		ID:    "broken",
		Name:  "失效网关",
		State: vpn.StateError,
		Error: "登录失败，请检查凭据",
	}
	tt := ui.NewTester(func(c *ui.Context) { a.pointCard(c, v) }, 720, 520)
	tt.Frame()
	if !tt.HasText(v.Error) {
		t.Fatal("未展开诊断时应显示失败原因")
	}
	if _, ok := tt.Find("登录 " + v.Name); !ok {
		t.Fatal("发生错误后应保留登录按钮")
	}
}

func TestPointLoginDoesNotOpenEditor(t *testing.T) {
	a := layoutApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	if err := tt.Click("登录 办公网线路"); err != nil {
		t.Fatal(err)
	}
	tt.Frame()
	if a.editor.open {
		t.Fatal("点击卡片的登录按钮不能同时打开编辑器")
	}
	if v, ok := a.mgr.View(a.cfg.Points[1].ID); !ok || v.State == vpn.StateOffline {
		t.Fatal("应开始登录所点击的接入点")
	}
}

// 分组策略：很少且同协议时平铺，跨协议或数量多时才按协议分组。
func TestUseProtocolGroups(t *testing.T) {
	mk := func(protos ...string) []vpn.View {
		out := make([]vpn.View, 0, len(protos))
		for i, p := range protos {
			out = append(out, vpn.View{ID: string(rune('a' + i)), Protocol: p})
		}
		return out
	}
	cases := []struct {
		name  string
		views []vpn.View
		want  bool
	}{
		{"没有接入点", mk(), false},
		{"只有一个", mk("atrust"), false},
		{"两个同协议", mk("atrust", "atrust"), false},
		{"两个不同协议", mk("atrust", "easyconnect"), true},
		{"三个同协议", mk("atrust", "atrust", "atrust"), true},
	}
	for _, c := range cases {
		if got := useProtocolGroups(c.views); got != c.want {
			t.Errorf("%s：useProtocolGroups = %v，想要 %v", c.name, got, c.want)
		}
	}
}

// 在线接入点可以通过常用入口直接断开。
func TestQuickTilesCarryActions(t *testing.T) {
	a := layoutApp(t)
	tiles := a.quickTiles()
	if len(tiles) == 0 {
		t.Fatal("在线接入点应当出现在常用入口里")
	}
	acts := 0
	for _, tile := range tiles {
		acts += len(tile.actions)
	}
	if acts == 0 {
		t.Fatalf("磁贴没有动作：%+v", tiles)
	}
	sawDisconnect := false
	for _, tile := range tiles {
		for _, act := range tile.actions {
			if strings.HasPrefix(act.label, "断开 ") {
				sawDisconnect = true
			}
		}
	}
	if !sawDisconnect {
		t.Error("在线接入点的磁贴应当能断开")
	}
}

// 只有一个接入点时列表直接平铺：不该出现协议组头。
func TestSmallSetRendersFlat(t *testing.T) {
	a := testApp(t)
	if _, err := a.store.Update(func(cfg *model.Config) error {
		cfg.Points = append(cfg.Points, model.AccessPoint{
			ID:       "only",
			Name:     "唯一网关",
			Protocol: model.ProtocolEasyConnect,
			Server:   "https://vpn.example.edu.cn",
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.cfg = a.store.Config()
	a.mgr.Apply(a.cfg)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, unwanted := range []string{"easyconnect", "atrust"} {
		if strings.Contains(texts, unwanted) {
			t.Errorf("单个接入点不该摆协议组头，却出现了 %q；texts = %s", unwanted, texts)
		}
	}
}

// 深色主题的强调绿只留给强调：选中底色要明显比强调色更接近背景。
func TestDarkAccentStaysForEmphasis(t *testing.T) {
	dark := softDark
	if dark.Selection == dark.Accent {
		t.Fatal("选中底色不该等于强调色")
	}
	// 色彩饱和度的粗量度：max-min 通道差。选中底色该明显低于强调色。
	chroma := func(c ui.Color) int {
		hi := max(int(c.R), int(c.G), int(c.B))
		lo := min(int(c.R), int(c.G), int(c.B))
		return hi - lo
	}
	if chroma(dark.Selection) >= chroma(dark.Accent) {
		t.Errorf("选中底色 %v 比强调色 %v 更花", dark.Selection, dark.Accent)
	}
	// 选中底色只该比背景亮一点，不能自己变成一个大色块。
	lum := func(c ui.Color) int {
		return (int(c.R)*299 + int(c.G)*587 + int(c.B)*114) / 1000
	}
	if lift := lum(dark.Selection) - lum(dark.Background); lift > 40 {
		t.Errorf("选中底色比背景亮了 %d，夜里看着像贴在屏幕上的色块", lift)
	}
}
