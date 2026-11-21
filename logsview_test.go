package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/qy/easyconnect/internal/vpn"
)

// 渲染只取最近 60 行，复制仍然拿 200 行。
func TestLastEntriesCapsRenderOnly(t *testing.T) {
	mk := func(n int) []vpn.LogEntry {
		out := make([]vpn.LogEntry, n)
		for i := range out {
			out[i] = vpn.LogEntry{Line: fmt.Sprintf("line-%03d", i)}
		}
		return out
	}
	cases := []struct {
		n, limit, want int
		firstLine      string
	}{
		{0, 60, 0, ""},
		{10, 60, 10, "line-000"},
		{60, 60, 60, "line-000"},
		{61, 60, 60, "line-001"},
		{200, 60, 60, "line-140"},
		{200, 0, 200, "line-000"},
	}
	for _, c := range cases {
		got := lastEntries(mk(c.n), c.limit)
		if len(got) != c.want {
			t.Errorf("lastEntries(%d, %d) = %d 条，想要 %d", c.n, c.limit, len(got), c.want)
			continue
		}
		if c.want > 0 && got[0].Line != c.firstLine {
			t.Errorf("lastEntries(%d, %d) 首行 = %q，想要 %q", c.n, c.limit, got[0].Line, c.firstLine)
		}
	}
}

// 日志回调按页面分档：看日志时立刻合并刷新，其它页面降到 1 秒。
func TestLogEventRoutesByVisibleViews(t *testing.T) {
	cases := []struct {
		name     string
		tab      int
		logs     bool
		settings bool
		section  int
		wantLog  bool
	}{
		{"接入点页", 0, false, false, 0, false},
		{"访问日志页", 2, false, false, 0, true},
		{"日志抽屉打开", 0, true, false, 0, true},
		{"设置页日志分区", 0, false, true, settingLogs, true},
		{"设置页通用分区", 0, false, true, settingGeneral, false},
	}
	for _, c := range cases {
		a := &app{}
		a.tab = c.tab
		a.logsOpen = c.logs
		a.settings.open = c.settings
		a.settings.section = c.section
		if got := a.logViewsVisible(); got != c.wantLog {
			t.Errorf("%s：logViewsVisible = %v，想要 %v", c.name, got, c.wantLog)
		}
	}
}

// 走一遍回调：非日志页只排 1 秒那一档，日志页排 33ms 那一档。
func TestLogEventUsesSlowPathOffLogPages(t *testing.T) {
	a := &app{}
	a.tab = 0
	a.onLogEvent()
	fastDraws, slowDraws, _, _, _ := a.redrawCounts()
	if fastDraws != 0 {
		t.Fatalf("非日志页不该立刻画，fast 档画了 %d 帧", fastDraws)
	}
	if _, _, _, coalesced, _ := a.redrawCounts(); coalesced == 0 && slowDraws != 0 {
		t.Log("slow 档已排队，等定时器到点再画")
	}
	a.tab = 2
	a.onLogEvent()
	if slowDraws != 0 {
		t.Fatalf("日志页不该走 1 秒档，slow 档画了 %d 帧", slowDraws)
	}
}

// 日志面板：排版 60 行、文案如实说明、复制按钮还在。
func TestLogPanelRendersLastSixty(t *testing.T) {
	a := testApp(t)
	a.logsOpen = true
	for i := 0; i < 100; i++ {
		a.bus.Add("app", fmt.Sprintf("marker-%03d", i))
	}
	// 运行日志面板在设置页的「日志」分区里。
	a.openSettingsAt(settingLogs)
	tt := ui.NewTester(a.view, 1120, 780)
	tt.Frame()
	texts := strings.Join(tt.Texts(), "|")
	for _, want := range []string{"marker-099", "marker-040", "显示最近 60 条，共 100 条", "复制全部"} {
		if !strings.Contains(texts, want) {
			t.Errorf("日志面板缺少 %q", want)
		}
	}
	for _, unwanted := range []string{"marker-000", "marker-039"} {
		if strings.Contains(texts, unwanted) {
			t.Errorf("第 41 条之前的日志不该被排版：%q 出现了", unwanted)
		}
	}
}
