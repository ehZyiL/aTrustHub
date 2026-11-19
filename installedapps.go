package main

import (
	"encoding/json"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
)

type installedAppsResult struct {
	apps []mygo.InstalledApp
	err  error
}

type installedAppsCatalog struct {
	apps    []mygo.InstalledApp
	pending <-chan installedAppsResult
	err     string
}

func (a *app) loadInstalledApps() {
	if a.localCatalog.pending != nil {
		return
	}
	results := make(chan installedAppsResult, 1)
	a.localCatalog.pending, a.localCatalog.err = results, ""
	window := a.win
	go func() {
		apps, err := mygo.Shell.InstalledApps()
		results <- installedAppsResult{apps: apps, err: err}
		if window != nil {
			window.Invalidate()
		}
	}()
}

func (a *app) installedAppsPicker(c *ui.Context) {
	d := &a.localEditor
	if !d.showInstalled {
		if ui.Button(c, "从已安装软件选择…").Clicked() {
			d.showInstalled = true
			if len(a.localCatalog.apps) == 0 {
				a.loadInstalledApps()
			}
		}
		return
	}
	catalog := &a.localCatalog
	select {
	case result := <-catalog.pending:
		catalog.pending = nil
		catalog.apps = result.apps
		if result.err != nil {
			catalog.err = "无法读取已安装软件，可以使用下方的浏览按钮手动选择"
		}
	default:
	}
	t := c.Theme()
	ui.Column(c).Gap(6).Padding(8).Border(1, t.Border).Radius(6).Children(func() {
		ui.Row(c).Gap(6).Children(func() {
			ui.TextInput(c, &d.appSearch).Placeholder("搜索 IDEA、Firefox、数据库工具…").Grow(1)
			if ui.Button(c, "重新扫描").Disabled(catalog.pending != nil).Clicked() {
				a.loadInstalledApps()
			}
			if ui.Button(c, "收起列表").Clicked() {
				d.showInstalled = false
			}
		})
		if catalog.pending != nil {
			ui.Text(c, "正在读取已安装软件…").FontSize(12)
			return
		}
		if catalog.err != "" {
			ui.Text(c, catalog.err).FontSize(12).TextColor(t.Warning).Wrap()
			return
		}
		query := strings.ToLower(strings.TrimSpace(d.appSearch))
		shown := 0
		ui.Scroll(c).MinHeight(80).MaxHeight(150).Children(func() {
			ui.Column(c).Gap(4).Children(func() {
				for _, entry := range catalog.apps {
					if !strings.Contains(strings.ToLower(entry.Name+" "+entry.ID), query) {
						continue
					}
					shown++
					if shown > 40 {
						ui.Text(c, "更多结果请缩小搜索范围").FontSize(11).TextColor(t.TextMuted)
						break
					}
					ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
						ui.Text(c, entry.Name).FontSize(12).Grow(1).Ellipsis("…")
						if ui.Button(c, "选择").Label("选择已安装软件 " + entry.ID).Clicked() {
							a.selectInstalledApp(entry)
						}
					})
				}
				if shown == 0 {
					ui.Text(c, "未找到匹配的软件，可以手动选择程序文件").FontSize(12).Wrap()
				}
			})
		})
	})
}

func (a *app) selectInstalledApp(entry mygo.InstalledApp) {
	program, err := readInstalledProgram(entry.Path)
	d := &a.localEditor
	if err != nil {
		d.err = err.Error()
		return
	}
	if strings.TrimSpace(d.name) == "" {
		d.name = entry.Name
	}
	d.executable, d.workDir = program.Executable, program.WorkDir
	d.args = ""
	if len(program.Args) != 0 {
		args, _ := json.Marshal(program.Args)
		d.args = string(args)
	}
	d.err, d.showInstalled = "", false
}
