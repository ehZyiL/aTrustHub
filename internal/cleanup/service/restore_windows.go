//go:build windows

package service

import (
	"context"
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
	return RestoreBackupContext(context.Background(), manifestPath, rw)
}

func RestoreBackupContext(ctx context.Context, manifestPath string, rw *ReportWriter) error {
	var manifest BackupManifest
	if err := readManifest(manifestPath, &manifest); err != nil {
		return err
	}
	backupDir := filepath.Dir(manifestPath)
	if err := validateRestore(backupDir, &manifest); err != nil {
		return err
	}

	if rw != nil {
		_ = rw.WriteEvent(ReportEvent{
			Event:    "start",
			BackupID: manifest.BackupID,
			Total:    len(manifest.Registry) + len(manifest.Files) + len(manifest.Certificates) + len(manifest.Policies),
		})
	}

	okCount := 0
	failedCount := 0

	// 1. 还原注册表
	for _, regItem := range manifest.Registry {
		if err := checkpoint(ctx, rw, "reg:"+regItem.Key); err != nil {
			return err
		}
		fullRegPath := filepath.Join(backupDir, regItem.BackupFile)
		args := []string{"import", fullRegPath}
		if regItem.View == "32" || regItem.View == "64" {
			args = append(args, "/reg:"+regItem.View)
		}
		cmd := exec.Command("reg.exe", args...)
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
		if err := checkpoint(ctx, rw, "file:"+fileItem.OriginalPath); err != nil {
			return err
		}
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
		if err := checkpoint(ctx, rw, "cert:"+certItem.Thumbprint); err != nil {
			return err
		}
		fullCertPath := filepath.Join(backupDir, certItem.BackupFile)
		args := []string{"-addstore", "-f", certItem.Store, fullCertPath}
		if certItem.LocalMachine != nil && !*certItem.LocalMachine {
			args = append([]string{"-user"}, args...)
		}
		cmd := exec.Command("certutil.exe", args...)
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

	for _, policy := range manifest.Policies {
		id := "policy:" + policy.Key + `\` + policy.Value
		if err := checkpoint(ctx, rw, id); err != nil {
			return err
		}
		status, message := StatusOk, "已还原策略值"
		if err := restorePolicyValue(policy); err != nil {
			failedCount++
			status, message = StatusFailed, fmt.Sprintf("还原策略值失败: %v", err)
		} else {
			okCount++
		}
		if rw != nil {
			_ = rw.WriteEvent(ReportEvent{Event: "item", ID: id, Status: status, Message: message})
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

	return rw.Err()
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

	out, err := os.CreateTemp(filepath.Dir(dst), ".connect-hub-restore-")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())

	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(out.Name(), dst)
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
