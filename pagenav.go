package main

import "github.com/egoist/mygo/ui"

// 导航里的四个页面：顺序与 ⌘1–⌘4 一致。
func pageNavLabels(a *app) []string {
	return []string{"接入点", appTabLabel(a.appCount()), accessTabLabel(), "本机软件"}
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
		for i, label := range pageNavLabels(a) {
			page := i
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
