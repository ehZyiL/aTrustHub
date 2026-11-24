//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/egoist/mygo/ui"
	"github.com/ehzyil/connect-hub/internal/sangforclean"
)

func (a *app) maintenanceSection(c *ui.Context) {
	a.initCleanupState()
	t := c.Theme()

	a.cleanup.mu.RLock()
	st := a.cleanup.status
	plan := a.cleanup.plan
	events := a.cleanup.events
	backups := a.cleanup.backups
	msg := a.cleanup.message
	errMsg := a.cleanup.err
	okCount := a.cleanup.okItems
	rebootCount := a.cleanup.rebootItems
	failedCount := a.cleanup.failedItems

	// 锁内深拷贝 selectedMap，彻底防止并发读写引发 Fatal Panic
	selectedSnapshot := make(map[string]bool, len(a.cleanup.selectedMap))
	for k, v := range a.cleanup.selectedMap {
		selectedSnapshot[k] = v
	}
	a.cleanup.mu.RUnlock()

	// 1. 官方卸载器引导卡片
	settingsGroup(c, "官方客户端检测与卸载", func() {
		if plan != nil && len(plan.Installed) > 0 {
			ui.Text(c, "检测到系统中已安装官方客户端。建议先通过官方卸载器完整卸载，再清理遗留残留。").
				FontSize(12).TextColor(t.TextMuted).Wrap()

			for _, inst := range plan.Installed {
				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, "• "+inst.Name).Bold().FontSize(13)
					if ui.Button(c, "启动官方卸载").FontSize(11).Clicked() {
						a.launchOfficialUninstaller(inst.UninstallString)
					}
				})
			}

			if msg != "" && strings.Contains(msg, "官方卸载") {
				ui.Text(c, "✓ "+msg).FontSize(12).TextColor(t.Success)
			}
			if errMsg != "" && strings.Contains(errMsg, "卸载") {
				ui.Text(c, "⚠ "+errMsg).FontSize(12).TextColor(t.Danger)
			}
		} else {
			ui.Text(c, "未检测到已注册的官方客户端主程序，或已经通过官方入口完成卸载。").
				FontSize(12).TextColor(t.TextMuted)
		}
	})

	// 2. 残留清理卡片
	settingsGroup(c, "深信服组件与网络驱动残留清理", func() {
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			if ui.Button(c, "重新扫描残留").FontSize(12).Disabled(st == cleanupStatusScanning || st == cleanupStatusApplying).Clicked() {
				a.runCleanupScan()
			}
			if msg != "" {
				ui.Text(c, msg).FontSize(12).TextColor(t.TextMuted)
			}
		})

		// 冲突互斥检测
		if a.tunOn.Load() {
			ui.Text(c, "⚠️ 全局 TUN 接管当前处于开启状态，请先断开连接再执行清理。").
				FontSize(12).TextColor(t.Danger)
			return
		}

		if plan == nil {
			if st != cleanupStatusScanning {
				ui.Text(c, "尚未进行扫描，点击「重新扫描残留」开始检测系统中的深信服残留。").
					FontSize(12).TextColor(t.TextMuted)
			}
			return
		}

		if len(plan.Findings) == 0 {
			ui.Text(c, "🎉 系统非常干净，未发现任何深信服相关的服务、驱动、注册表或网络注入残留。").
				FontSize(13).TextColor(t.Success)
			return
		}

		ui.Text(c, "勾选需要清理的组件（建议项已默认勾选，深度项涉及第三方网络工具或网卡需谨慎勾选）：").
			FontSize(12).TextColor(t.TextMuted)

		// 清单列表（支持多项时滚动查看）
		ui.Scroll(c).MaxHeight(260).Children(func() {
			ui.Column(c).Gap(6).Children(func() {
				for _, f := range plan.Findings {
					id := f.ID
					val := selectedSnapshot[id]

					label := fmt.Sprintf("[%s] %s - %s", f.Group, f.Title, f.Detail)
					if f.Risk == sangforclean.RiskDeep {
						label = "⚠️ (深度) " + label
					}

					if ui.Checkbox(c, &val, label).Changed() {
						a.cleanup.mu.Lock()
						a.cleanup.selectedMap[id] = val
						a.cleanup.mu.Unlock()
					}
				}
			})
		})

		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			applyBtn := ui.Button(c, "开始清理并备份").FontSize(12).
				Disabled(st == cleanupStatusScanning || st == cleanupStatusApplying)

			if applyBtn.Clicked() {
				a.runCleanupApply()
			}

			ui.Text(c, "清理前将自动在 AppData 建立全量镜像快照，支持误删一键还原").
				FontSize(11).TextColor(t.TextMuted)
		})
	})

	// 3. 执行状态与报告卡片
	if len(events) > 0 || st == cleanupStatusApplying || st == cleanupStatusDone || st == cleanupStatusFailed {
		settingsGroup(c, "执行日志与结果", func() {
			if errMsg != "" {
				ui.Text(c, "错误: "+errMsg).FontSize(12).TextColor(t.Danger)
			}

			if st == cleanupStatusDone || (st == cleanupStatusFailed && (okCount > 0 || rebootCount > 0)) {
				summary := fmt.Sprintf("统计: 成功 %d 项, 重启生效 %d 项, 失败 %d 项", okCount, rebootCount, failedCount)
				color := t.Success
				if failedCount > 0 {
					color = t.Warning
				}
				ui.Text(c, summary).Bold().FontSize(13).TextColor(color)
				if rebootCount > 0 {
					ui.Text(c, "部分虚拟网卡驱动或被占用的文件已登记在系统重启后删除，建议重启电脑。").
						FontSize(12).TextColor(t.Warning)
				}
			}

			// 滚动日志条目（支持垂直滚动与长路径自动换行）
			ui.Scroll(c).MaxHeight(180).Children(func() {
				ui.Column(c).Gap(4).Children(func() {
					for _, ev := range events {
						if strings.TrimSpace(ev.Message) == "" {
							continue // 过滤无文字信息的内部控制事件
						}
						prefix := "• "
						switch ev.Status {
						case sangforclean.StatusOk:
							prefix = "✓ "
						case sangforclean.StatusFailed:
							prefix = "✗ "
						case sangforclean.StatusReboot:
							prefix = "⏳ "
						}
						ui.Text(c, prefix+ev.Message).FontSize(11).TextColor(t.TextMuted).Wrap()
					}
				})
			})
		})
	}

	// 4. 备份历史与一键还原卡片
	settingsGroup(c, "清理备份历史与一键还原", func() {
		if len(backups) == 0 {
			ui.Text(c, "暂无备份历史。每次执行清理前系统都会自动创建无损还原点。").
				FontSize(12).TextColor(t.TextMuted)
		} else {
			ui.Text(c, "如因误清理导致网络或软件异常，可在此选择还原点一键回退：").
				FontSize(12).TextColor(t.TextMuted)

			for _, b := range backups {
				manifestPath := filepath.Join(sangforclean.DefaultBackupRootDir(), b.BackupID, "manifest.json")
				bInfo := fmt.Sprintf("快照 %s (文件: %d, 注册表: %d, 证书: %d)",
					b.CreatedAt.Format("2006-01-02 15:04:05"),
					len(b.Files), len(b.Registry), len(b.Certificates))

				ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
					ui.Text(c, bInfo).FontSize(12)
					if ui.Button(c, "还原此备份").FontSize(11).
						Disabled(st == cleanupStatusApplying || st == cleanupStatusRestoring).Clicked() {
						a.runCleanupRestore(manifestPath)
					}
				})
			}
		}
	})
}
