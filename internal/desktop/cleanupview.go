package desktop

import (
	"fmt"
	"path/filepath"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/components"
)

func (a *app) maintenanceSection(c *ui.Context) {
	s := &a.cleanup
	t := c.Theme()
	settingsGroup(c, "深信服组件与网络驱动残留", func() {
		ui.Text(c, "扫描和清理按任务运行。先卸载官方客户端，再检查残留；深度项默认不选。").FontSize(12).TextColor(t.TextMuted).Wrap()
		ui.Row(c).Gap(10).Children(func() {
			if ui.Button(c, "扫描残留").Disabled(s.busy).Clicked() {
				a.startCleanup(contract.Request{Request: components.Request{Operation: contract.Scan}})
			}
			if ui.Button(c, "查询备份").Disabled(s.busy).Clicked() {
				a.startCleanup(contract.Request{Request: components.Request{Operation: contract.List}})
			}
			if ui.Button(c, "打开清理记录目录").Clicked() {
				if err := mygo.Shell.OpenExternal(filepath.Join(a.dir, "cleanup")); err != nil {
					s.view.Component.Detail = err.Error()
				}
			}
			if s.busy && ui.Button(c, "取消任务").Clicked() {
				a.cancelCleanup()
			}
		})
		if s.view.Component.Detail != "" {
			ui.Text(c, s.view.Component.Detail).FontSize(12).TextColor(t.TextMuted).Wrap()
		}
		if len(s.view.Installed) > 0 {
			for _, name := range s.view.Installed {
				ui.Text(c, "已安装："+name).FontSize(12)
			}
			if ui.Button(c, "打开 Windows 卸载设置").Clicked() {
				if err := mygo.Shell.OpenExternal("ms-settings:appsfeatures"); err != nil {
					s.view.Component.Detail = err.Error()
				}
			}
		}
		if s.view.Result.Truncated {
			ui.Text(c, "结果较多，本页仅显示有限条目；完整扫描保留在本次任务记录中。").FontSize(12).TextColor(t.Warning).Wrap()
		}
		if len(s.view.Findings) > 0 {
			ui.Scroll(c).MaxHeight(260).Children(func() {
				ui.Column(c).Gap(6).Children(func() {
					for _, f := range s.view.Findings {
						v := s.selected[f.ID]
						label := fmt.Sprintf("[%s] %s · %s", f.Group, f.Title, f.Detail)
						if f.Deep {
							label = "深度项 · " + label
						}
						if !s.busy && ui.Checkbox(c, &v, label).Changed() {
							s.selected[f.ID] = v
						} else if s.busy {
							ui.Text(c, label).FontSize(12).Wrap()
						}
					}
				})
			})
			if ui.Button(c, "备份并清理所选项").Disabled(s.busy).Clicked() {
				s.confirm = contract.Apply
			}
		}
		if s.view.Done && s.view.Operation == contract.Scan && s.view.Result.Outcome == "complete" {
			ui.Text(c, fmt.Sprintf("扫描完成，发现 %d 项。", s.view.Result.Total)).FontSize(12)
		}
		if s.view.Done && (s.view.Operation == contract.Apply || s.view.Operation == contract.Restore) {
			ui.Text(c, fmt.Sprintf("成功 %d 项 · 已不存在/跳过 %d 项 · 失败 %d 项 · 重启生效 %d 项", s.view.Result.OK, s.view.Result.Skipped, s.view.Result.Failed, s.view.Result.Reboot)).FontSize(12).Wrap()
			if s.view.Result.BackupID != "" {
				ui.Text(c, "备份："+s.view.Result.BackupID).FontSize(11).Wrap()
			}
		}
	})
	if len(s.view.Backups) > 0 {
		settingsGroup(c, "备份与恢复", func() {
			for _, b := range s.view.Backups {
				ui.Row(c).Gap(10).Children(func() {
					ui.Text(c, fmt.Sprintf("%s · 文件 %d · 注册表 %d · 证书 %d · 策略 %d", b.CreatedAt.Format("2006-01-02 15:04"), b.Files, b.Registry, b.Certificates, b.Policies)).FontSize(12)
					if ui.Button(c, "恢复此备份").Disabled(s.busy).Clicked() {
						s.backupID = b.ID
						s.confirm = contract.Restore
					}
				})
			}
		})
	}
	if s.confirm != "" && !s.busy {
		settingsGroup(c, "确认操作", func() {
			ui.Text(c, "清理会修改所选系统组件；备份可恢复已保存的文件、注册表和证书，驱动或程序可能仍需重新安装。取消会等待当前单项操作完成。").FontSize(12).Wrap()
			ui.Row(c).Gap(10).Children(func() {
				if ui.Button(c, "确认执行").Clicked() {
					op := s.confirm
					s.confirm = ""
					a.startCleanup(contract.Request{Request: components.Request{Operation: op}, BackupID: s.backupID})
				}
				if ui.Button(c, "返回检查").Clicked() {
					s.confirm = ""
				}
			})
		})
	}
	if len(s.view.Logs) > 0 {
		settingsGroup(c, "任务进度", func() {
			ui.Scroll(c).MaxHeight(180).Children(func() {
				ui.Column(c).Gap(4).Children(func() {
					for _, line := range s.view.Logs {
						ui.Text(c, line).FontSize(11).TextColor(t.TextMuted).Wrap()
					}
				})
			})
		})
	}
}
