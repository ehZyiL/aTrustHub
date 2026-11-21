package main

import "github.com/egoist/mygo/ui"

// pageRef 是顶栏导航里的一段：Tab 是 a.tab 的逻辑页号，Label 是显示文案。
// 简单模式只换掉「出现哪几段」，不改 a.tab 的含义——其余代码照旧按逻辑页号
// 分发，不必到处判断模式。
type pageRef struct {
	Tab   int
	Label string
}

// pages 是当前模式下顶栏的段。简单模式下为单页面应用，不需要顶部分段 Tab；
// 完整模式下保留四段。
func (a *app) pages() []pageRef {
	if a.simpleMode() {
		return nil
	}
	return []pageRef{
		{Tab: 0, Label: "接入点"},
		{Tab: 1, Label: appTabLabel(a.appCount())},
		{Tab: 2, Label: accessTabLabel()},
		{Tab: 3, Label: "本机软件"},
	}
}

// clampTab 把 a.tab 收敛到当前模式下存在的页面：切进简单模式时
// 收敛到唯一的首页 0。
func (a *app) clampTab() {
	if a.simpleMode() {
		a.tab = 0
		return
	}
	for _, ref := range a.pages() {
		if ref.Tab == a.tab {
			return
		}
	}
	a.tab = 0
}

// goTab 切页并离开设置页。设置是页面级的东西：切页就该回到页面本身，
// 这也是「点设置后再点接入点没反应」的根因所在。
func (a *app) goTab(page int) {
	a.tab = page
	a.settings.open = false
	a.invalidate()
}

// pageNav 是顶栏的分段导航。每一段都是一次显式的切页动作，所以即使点的
// 是当前页，也能从设置页回到该页——ui.Segmented 绑定同一个值时不会报变化。
func (a *app) pageNav(c *ui.Context) {
	t := c.Theme()
	track := ui.Row(c).Padding(3).Radius(999).Background(t.SurfaceHover).
		Border(1, t.Border).Gap(2)
	track.Children(func() {
		for _, ref := range a.pages() {
			page := ref.Tab
			label := ref.Label
			active := !a.settings.open && a.tab == page
			seg := ui.Row(c).Padding(5, 12).Radius(999).OnClick(func() { a.goTab(page) })
			if active {
				seg = seg.Background(t.Surface).Shadow(0, 1, 3, 0, cardShadow(t))
			}
			seg.Children(func() {
				colour := t.TextMuted
				if active {
					colour = t.Text
				}
				ui.Text(c, label).FontSize(11).TextColor(colour)
			})
		}
	})
}
