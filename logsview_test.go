package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/vpn"
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

// 只有「日志面板真的在画」才算在看日志：
// 离开设置后 logsOpen 还留着 true，不能因此就走 30 FPS 那一档。
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
		{"日志面板打开", 0, true, true, settingLogs, true},
		{"日志分区但面板收着", 0, false, true, settingLogs, false},
		{"离开设置后 logsOpen 残留", 0, true, false, 0, false},
		{"设置页通用分区", 0, true, true, settingGeneral, false},
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

// 事件源按档排队：日志页排 33ms，其它页面排 1 秒。
// 用注入的假时钟断言「排了哪一档」——只看到点后画了几帧的话，没到点永远都是 0。
func TestLogEventUsesTheRightScheduler(t *testing.T) {
	a := &app{}
	a.painter()
	fast, slow := &fakeSchedule{}, &fakeSchedule{}
	a.redrawFast.schedule = fast.schedule
	a.redrawSlow.schedule = slow.schedule

	// 接入点页：只排慢档。
	a.tab = 0
	a.syncLogViewActive()
	a.onLogEvent()
	if fast.armed() {
		t.Error("非日志页不该排快档")
	}
	if !slow.armed() {
		t.Fatal("非日志页应当排 1 秒档")
	}
	if slow.delay != redrawSlowInterval {
		t.Errorf("慢档间隔 = %v，想要 %v", slow.delay, redrawSlowInterval)
	}
	slow.fire()

	// 访问日志页：只排快档。
	a.tab = 2
	a.syncLogViewActive()
	a.onLogEvent()
	if !fast.armed() {
		t.Error("日志页应当排 33ms 档")
	}
	if fast.delay != redrawFastInterval {
		t.Errorf("快档间隔 = %v，想要 %v", fast.delay, redrawFastInterval)
	}
}

// 判定在主线程算成原子快照，回调只读快照：日志 goroutine 不碰 settings / tab。
func TestLogViewSnapshotDrivesCallback(t *testing.T) {
	a := &app{}
	a.painter()
	fast, slow := &fakeSchedule{}, &fakeSchedule{}
	a.redrawFast.schedule = fast.schedule
	a.redrawSlow.schedule = slow.schedule

	a.tab = 2
	a.syncLogViewActive()
	if !a.logViewActive.Load() {
		t.Fatal("访问日志页的快照应当为 true")
	}
	a.onLogEvent()
	if !fast.armed() || slow.armed() {
		t.Error("日志页应当只排快档")
	}
	fast.fire()

	a.tab = 0
	a.syncLogViewActive()
	if a.logViewActive.Load() {
		t.Fatal("离开日志页后快照应当为 false")
	}
	a.onLogEvent()
	if !slow.armed() || fast.armed() {
		t.Error("离开日志页后应当只排慢档")
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
