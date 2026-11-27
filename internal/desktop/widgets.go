package desktop

import (
	"github.com/egoist/mygo/ui"
)

// logIcon is a small document-with-lines glyph for the TUN log button.
// copyIcon is two overlapping sheets, for "copy this address".
var copyIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>`))

// refreshIcon is the two-arrow refresh glyph used by aTrust's own console, for
// "check this session again".
var refreshIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 1024 1024" fill="currentColor"><path d="M168 504.2c1-43.7 10-86.1 26.9-126 17.3-41 42.1-77.7 73.7-109.4S337 212.3 378 195c42.4-17.9 87.4-27 133.9-27s91.5 9.1 133.8 27c40.9 17.3 77.7 42.1 109.3 73.8 9.9 9.9 19.2 20.4 27.8 31.4l-60.2 47c-5.3 4.1-3.5 12.5 3 14.1l175.7 43c5 1.2 9.9-2.6 9.9-7.7l0.8-180.9c0-6.7-7.7-10.5-12.9-6.3l-56.4 44.1C765.8 155.1 646.2 92 511.8 92 282.7 92 96.3 275.6 92 503.8c-0.1 4.5 3.5 8.2 8 8.2h60c4.4 0 7.9-3.5 8-7.8z m756 7.8h-60c-4.4 0-7.9 3.5-8 7.8-1 43.7-10 86.1-26.9 126-17.3 41-42.1 77.8-73.7 109.4S687 811.7 646 829c-42.4 17.9-87.4 27-133.9 27s-91.5-9.1-133.9-27c-40.9-17.3-77.7-42.1-109.3-73.8-9.9-9.9-19.2-20.4-27.8-31.4l60.2-47c5.3-4.1 3.5-12.5-3-14.1l-175.7-43c-5-1.2-9.9 2.6-9.9 7.7l-0.7 181c0 6.7 7.7 10.5 12.9 6.3l56.4-44.1C258.2 868.9 377.8 932 512.2 932c229.2 0 415.5-183.7 419.8-411.8 0.1-4.5-3.5-8.2-8-8.2z"/></svg>`))

// iconButton draws a small clickable glyph, the same shape as the TUN log
// button, so one-row actions do not take a full button's width.
func iconButton(c *ui.Context, icon *ui.SVG, tooltip string, onClick func()) {
	ui.Row(c).Padding(4).Radius(8).AlignItems(ui.Center).
		OnClick(onClick).Tooltip(tooltip).Children(func() {
		ui.Icon(c, icon).Size(15, 15)
	})
}

var logIcon = ui.MustParseSVG([]byte(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/></svg>`))

// groupBar 画分组头共用的那一行：折叠箭头、可选状态灯、名称、可选状态文字、
// 计数和右侧动作。资源分组与本机项目分组都用它，两处形状不会走样。
func groupBar(c *ui.Context, collapsed bool, dot ui.Color, name, status, count string, onToggle func(), trailing func()) {
	t := c.Theme()
	arrow := "▾"
	if collapsed {
		arrow = "▸"
	}
	bar := ui.Row(c).Padding(8, 12).Gap(8).AlignItems(ui.Center).Background(t.Background)
	bar.OnClick(onToggle)
	bar.Children(func() {
		ui.Text(c, arrow).FontSize(11).TextColor(t.TextMuted)
		if dot != ui.Transparent {
			ui.Row(c).Size(6, 6).Radius(3).Background(dot)
		}
		ui.Text(c, name).FontSize(13).Bold().Ellipsis("…")
		if status != "" {
			ui.Text(c, status).FontSize(11).TextColor(t.TextMuted)
		}
		ui.Row(c).Grow(1)
		ui.Text(c, count).FontSize(11).TextColor(t.TextMuted)
		if trailing != nil {
			trailing()
		}
	})
}

// appMark 画资源行首的字母色块：浅底 + 细描边 + 同色字母，比实心色块安静。
func appMark(c *ui.Context, t *ui.Theme, name string) {
	ui.Row(c).Size(28, 28).Radius(9).Background(t.Surface).Border(1, t.Border).
		AlignItems(ui.Center).Justify(ui.Center).Children(func() {
		ui.Text(c, firstRune(name)).FontSize(13).Bold().
			TextColor(glyphColor(t, name))
	})
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return "应"
}

// pageBar 是每个页面内容顶部的上下文栏：左边标题与计数，右边本页的过滤、搜索
// 与主操作。四个页面都用它，操作位置因此一致。
func pageBar(c *ui.Context, title, count string, trailing func()) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
		ui.Text(c, title).FontSize(17).Bold()
		if count != "" {
			ui.Text(c, count).FontSize(12).TextColor(t.TextMuted)
		}
		ui.Row(c).Grow(1)
		trailing()
	})
}

// noResults 是列表内的「没有结果」提示：留白、字号与层次统一，
// 与整页空状态（emptyState 类的面板）区分开。
func noResults(c *ui.Context, title, hint string) {
	t := c.Theme()
	ui.Column(c).Padding(24).Gap(4).Center().Children(func() {
		ui.Text(c, title).FontSize(13).Bold()
		if hint != "" {
			ui.Text(c, hint).FontSize(11).TextColor(t.TextMuted).
				Wrap().MaxWidth(460)
		}
	})
}

// metaCopy draws "key value" with the copy glyph right next to the value: a
// loose row gap left the icon floating far from what it copies.
func metaCopy(c *ui.Context, t *ui.Theme, key, value, tooltip string, onClick func()) {
	ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Text(c, key).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(11).Font("monospace").TextColor(t.Text)
		ui.Row(c).Padding(3).Radius(8).AlignItems(ui.Center).
			OnClick(onClick).Tooltip(tooltip).Children(func() {
			ui.Icon(c, copyIcon).Size(13, 13)
		})
	})
}

func meta(c *ui.Context, t *ui.Theme, key, value string) {
	ui.Row(c).Gap(5).AlignItems(ui.Center).Children(func() {
		ui.Text(c, key).FontSize(11).TextColor(t.TextMuted)
		ui.Text(c, value).FontSize(11).Font("monospace").TextColor(t.Text)
	})
}

// ---- dialogs ----

// 弹窗共用的宽度档位：确认类窄、详情类常规、表单类宽。
const (
	dialogNarrow  float32 = 460
	dialogRegular float32 = 560
	dialogWide    float32 = 640
)

// dialogHeader 是弹窗标题区：标题、可选的副标题，下面一条分隔线。
// 所有弹窗都从这里开始，字号、间距和分隔线才不会各写一套。
func dialogHeader(c *ui.Context, title, subtitle string) {
	t := c.Theme()
	ui.Column(c).Gap(3).Children(func() {
		ui.Text(c, title).FontSize(15).Bold()
		if subtitle != "" {
			ui.Text(c, subtitle).FontSize(11).TextColor(t.TextMuted).Wrap()
		}
	})
	ui.Divider(c)
}

// dialogFooter 是弹窗底部动作区：分隔线 + 一行按钮，左侧留给删除之类的
// 次要动作，右侧放取消与确认。
func dialogFooter(c *ui.Context, fn func()) {
	ui.Divider(c)
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(fn)
}

// 弹窗正文的高度上下限（DIP）：太小看不见内容，太大则把页脚挤出面板。
const (
	dialogBodyMin float32 = 140
	dialogBodyMax float32 = 380
)

// dialogBodyMaxHeight 计算弹窗内滚动正文的安全高度上限：
// 从窗口内容区高度中预留出充足空间，包括：
// - Modal 面板外层相对窗口的上下边距（mygo 预留 40 DIP）
// - Modal 面板内部 padding（上下各 20 DIP，共 40 DIP）
// - dialogHeader（约 50 DIP）
// - dialogFooter（约 45 DIP）
// - 容器内组件间距 Gap（约 20 DIP）
// - 安全缓冲裕量（约 45 DIP，适应不同 DPI、系统字号与窗口修饰）
// 固定开销总计预留 240 DIP。在窗口高度 600 时正文约 320 DIP，在最小高度 520 时正文约 248 DIP。
// 这样可以确保弹窗在任何屏幕和窗口缩放比例下，底部的保存/取消按钮永远 100% 显露在视口内。
func (a *app) dialogBodyMaxHeight() float32 {
	h := a.windowH - 240
	if h < dialogBodyMin {
		h = dialogBodyMin
	}
	if h > dialogBodyMax {
		h = dialogBodyMax
	}
	return h
}

// dialogBodyHeight 兼容旧接口，直接基于全局安全的 dialogBodyMaxHeight 计算。
func (a *app) dialogBodyHeight(reserved float32) float32 {
	return a.dialogBodyMaxHeight()
}
