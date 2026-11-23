//go:build windows

package sangforclean

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// RestoreBackup 从指定的 manifest.json 执行一键还原
func RestoreBackup(manifestPath string, rw *ReportWriter) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("读取备份清单失败: %w", err)
	}

	var manifest BackupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("解析备份清单失败: %w", err)
	}

	backupDir := filepath.Dir(manifestPath)

	if rw != nil {
		_ = rw.WriteEvent(ReportEvent{
			Event:    "start",
			BackupID: manifest.BackupID,
			Total:    len(manifest.Registry) + len(manifest.Files) + len(manifest.Certificates),
		})
	}

	okCount := 0
	failedCount := 0

	// 1. 还原注册表
	for _, regItem := range manifest.Registry {
		fullRegPath := filepath.Join(backupDir, regItem.BackupFile)
		cmd := exec.Command("reg.exe", "import", fullRegPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			failedCount++
			if rw != nil {
				_ = rw.WriteEvent(ReportEvent{
					Event:   "item",
					ID:      "reg:" + regItem.Key,
					Status:  StatusFailed,
					Message: fmt.Sprintf("还原注册表失败: %v", err),
				})
			}
		} else {
			okCount++
			if rw != nil {
				_ = rw.WriteEvent(ReportEvent{
					Event:   "item",
					ID:      "reg:" + regItem.Key,
					Status:  StatusOk,
					Message: "已还原注册表项",
				})
			}
		}
	}

	// 2. 还原文件
	for _, fileItem := range manifest.Files {
		fullBackupPath := filepath.Join(backupDir, fileItem.BackupPath)
		if err := restoreSingleFile(fullBackupPath, fileItem.OriginalPath); err != nil {
			failedCount++
			if rw != nil {
				_ = rw.WriteEvent(ReportEvent{
					Event:   "item",
					ID:      "file:" + fileItem.OriginalPath,
					Status:  StatusFailed,
					Message: fmt.Sprintf("还原文件失败: %v", err),
				})
			}
		} else {
			okCount++
			if rw != nil {
				_ = rw.WriteEvent(ReportEvent{
					Event:   "item",
					ID:      "file:" + fileItem.OriginalPath,
					Status:  StatusOk,
					Message: "已还原文件",
				})
			}
		}
	}

	// 3. 还原证书
	for _, certItem := range manifest.Certificates {
		fullCertPath := filepath.Join(backupDir, certItem.BackupFile)
		cmd := exec.Command("certutil.exe", "-addstore", "-f", certItem.Store, fullCertPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if err := cmd.Run(); err != nil {
			failedCount++
			if rw != nil {
				_ = rw.WriteEvent(ReportEvent{
					Event:   "item",
					ID:      "cert:" + certItem.Thumbprint,
					Status:  StatusFailed,
					Message: fmt.Sprintf("还原证书失败: %v", err),
				})
			}
		} else {
			okCount++
			if rw != nil {
				_ = rw.WriteEvent(ReportEvent{
					Event:   "item",
					ID:      "cert:" + certItem.Thumbprint,
					Status:  StatusOk,
					Message: "已还原根证书",
				})
			}
		}
	}

	exitCode := 0
	if failedCount > 0 {
		exitCode = 1
	}

	if rw != nil {
		_ = rw.WriteEvent(ReportEvent{
			Event:  "end",
			Ok:     okCount,
			Failed: failedCount,
			Exit:   exitCode,
		})
	}

	if failedCount > 0 {
		return fmt.Errorf("还原过程中有 %d 项失败", failedCount)
	}

	return nil
}

func restoreSingleFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// ListBackups 列出指定根目录下所有可用的备份点
func ListBackups(backupRootDir string) ([]BackupManifest, error) {
	if backupRootDir == "" {
		backupRootDir = DefaultBackupRootDir()
	}

	entries, err := os.ReadDir(backupRootDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var result []BackupManifest
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		mPath := filepath.Join(backupRootDir, e.Name(), "manifest.json")
		data, err := os.ReadFile(mPath)
		if err != nil {
			continue
		}
		var m BackupManifest
		if err := json.Unmarshal(data, &m); err == nil {
			result = append(result, m)
		}
	}
	return result, nil
}
