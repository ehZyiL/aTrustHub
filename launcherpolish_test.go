package main

import (
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/model"
	"github.com/qy/easyconnect/internal/vpn"
)

// 底栏只报运行环境：接管方式留在顶栏，同一个东西不该有两个入口。
func TestEnvStripIsRuntimeOnly(t *testing.T) {
	a := layoutApp(t)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	if !strings.Contains(texts, "运行环境") {
		t.Errorf("底栏缺少「运行环境」；texts = %s", texts)
	}
	for _, want := range []string{"在线 1 / 3", "本机项目 0 个运行中", "助手 "} {
		if !strings.Contains(texts, want) {
			t.Errorf("底栏缺少 %q", want)
		}
	}
	// 顶栏的网络状态入口会写一次「接管」，底栏再写一次就算重复。
	if n := strings.Count(texts, "接管"); n > 1 {
		t.Errorf("「接管」出现了 %d 次，底栏不该重复；texts = %s", n, texts)
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

// 常用入口的磁贴带动作：在线接入点能断开，运行中的本机项目能停止或查看。
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
