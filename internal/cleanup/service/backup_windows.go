//go:build windows

package service

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ehzyil/connect-hub/internal/cleanup/contract"
	"github.com/ehzyil/connect-hub/internal/cleanup/taskio"
	"github.com/ehzyil/connect-hub/internal/components"
	"golang.org/x/sys/windows"
)

// DefaultBackupRootDir 获取默认备份根目录（统一使用 connect-hub 主数据目录，并自动平滑兼容历史旧目录）
func DefaultBackupRootDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	target := filepath.Join(appData, "connect-hub", "cleanup", "backups")
	for _, legacyName := range []string{"ConnectHub", "Connect Hub"} {
		legacy := filepath.Join(appData, legacyName, "cleanup", "backups")
		migrateLegacyBackups(legacy, target)
	}
	return target
}

// migrateLegacyBackups 平滑迁移历史旧目录中的备份并清理空目录
func migrateLegacyBackups(legacyRoot, targetRoot string) {
	entries, err := os.ReadDir(legacyRoot)
	if err != nil {
		return
	}
	if err := os.MkdirAll(targetRoot, 0755); err != nil {
		return
	}
	for _, e := range entries {
		src := filepath.Join(legacyRoot, e.Name())
		dst := filepath.Join(targetRoot, e.Name())
		if _, err := os.Stat(dst); os.IsNotExist(err) {
			_ = os.Rename(src, dst)
		}
	}
	// 尝试逐级清理已清空的旧目录
	_ = os.Remove(legacyRoot)
	cleanupParent := filepath.Dir(legacyRoot)
	_ = os.Remove(cleanupParent)
	connectHubParent := filepath.Dir(cleanupParent)
	_ = os.Remove(connectHubParent)
}

// CreateBackup 执行全量快照备份并输出 BackupManifest
func CreateBackup(plan *Plan, backupRootDir string) (*BackupManifest, error) {
	return CreateBackupContext(context.Background(), plan, backupRootDir)
}

func CreateBackupContext(ctx context.Context, plan *Plan, backupRootDir string) (*BackupManifest, error) {
	if backupRootDir == "" {
		backupRootDir = DefaultBackupRootDir()
	}

	id, err := components.NewID()
	if err != nil {
		return nil, err
	}
	backupID := time.Now().Format("20060102-150405") + "-" + id
	backupDir := filepath.Join(backupRootDir, backupID)

	regDir := filepath.Join(backupDir, "registry")
	fileDir := filepath.Join(backupDir, "files")
	certDir := filepath.Join(backupDir, "certs")

	for _, d := range []string{regDir, fileDir, certDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("创建备份目录失败 %s: %w", d, err)
		}
	}

	manifest := &BackupManifest{
		Version:      1,
		BackupID:     backupID,
		CreatedAt:    time.Now(),
		PlanSnapshot: "plan.json",
		Registry:     make([]RegistryBackupItem, 0),
		Files:        make([]FileBackupItem, 0),
		Certificates: make([]CertBackupItem, 0),
		Policies:     make([]PolicyBackupItem, 0),
	}

	// 1. 保存 plan 快照
	planSnapshotPath := filepath.Join(backupDir, "plan.json")
	if err := SavePlanToFile(planSnapshotPath, plan); err != nil {
		return nil, fmt.Errorf("保存 plan 快照失败: %w", err)
	}

	// 2. 备份注册表项
	for _, f := range plan.Findings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !f.Selected {
			continue
		}

		if f.Action == ActionDeleteRegistry {
			hive, _ := f.Params["hive"].(string)
			key, _ := f.Params["key"].(string)
			view, _ := f.Params["view"].(string)

			if hive != "" && key != "" {
				fullKey := hive + `\` + key
				safeName := strings.ReplaceAll(strings.ReplaceAll(fullKey, `\`, `_`), `:`, `_`) + "_" + view
				backupRel := filepath.Join("registry", safeName+".reg")
				backupDest := filepath.Join(backupDir, backupRel)

				args := []string{"export", fullKey, backupDest, "/y"}
				if view == "32" || view == "64" {
					args = append(args, "/reg:"+view)
				}
				cmd := exec.CommandContext(ctx, "reg.exe", args...)
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				if err := cmd.Run(); err != nil {
					return nil, fmt.Errorf("备份注册表失败 %s: %w", fullKey, err)
				}

				if _, err := os.Stat(backupDest); err == nil {
					manifest.Registry = append(manifest.Registry, RegistryBackupItem{
						Hive:       hive,
						Key:        key,
						View:       view,
						BackupFile: backupRel,
					})
				}
			}
		} else if f.Action == ActionDeletePath {
			path, _ := f.Params["path"].(string)
			if path == "" {
				continue
			}

			if err := backupFileOrDir(path, fileDir, backupDir, manifest); err != nil {
				return nil, fmt.Errorf("备份文件失败 %s: %w", path, err)
			}
		} else if f.Action == ActionDeleteCert {
			thumbprint, _ := f.Params["thumbprint"].(string)
			subject, _ := f.Params["subject"].(string)
			store, _ := f.Params["store"].(string)
			localMachine, hasScope := f.Params["localMachine"].(bool)

			if thumbprint != "" {
				certRel := filepath.Join("certs", fmt.Sprintf("%t-%s.cer", localMachine, thumbprint))
				certDest := filepath.Join(backupDir, certRel)
				var scope *bool
				if hasScope {
					scope = &localMachine
				}
				if err := exportCertificateScope(store, thumbprint, certDest, scope); err != nil {
					return nil, err
				} else {
					manifest.Certificates = append(manifest.Certificates, CertBackupItem{
						Store:        store,
						Thumbprint:   thumbprint,
						Subject:      subject,
						BackupFile:   certRel,
						LocalMachine: scope,
					})
				}
			}
		}
	}

	// 3. 写出 manifest.json
	manifestPath := filepath.Join(backupDir, "manifest.json")
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if len(data) > contract.MaxPlanBytes {
		return nil, errors.New("备份清单超过上限，停止清理")
	}
	if err := taskio.WriteBytes(filepath.Dir(manifestPath), filepath.Base(manifestPath), data); err != nil {
		return nil, fmt.Errorf("保存 manifest 失败: %w", err)
	}

	return manifest, nil
}

func backupFileOrDir(srcPath, fileBackupRoot, backupDir string, manifest *BackupManifest) error {
	fi, err := os.Lstat(srcPath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("备份源不能是链接")
	}

	if fi.IsDir() {
		return filepath.Walk(srcPath, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info == nil {
				return errors.New("备份文件信息缺失")
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("备份路径包含链接")
			}
			if info.IsDir() {
				return nil
			}
			return backupSingleFile(p, fileBackupRoot, backupDir, manifest)
		})
	}

	return backupSingleFile(srcPath, fileBackupRoot, backupDir, manifest)
}

func backupSingleFile(srcPath, fileBackupRoot, backupDir string, manifest *BackupManifest) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}

	if fi.Size() > 200*1024*1024 {
		return errors.New("文件超过单项备份上限，停止清理")
	}

	vol := filepath.VolumeName(srcPath)
	noVol := strings.TrimPrefix(srcPath, vol)
	noVol = strings.TrimPrefix(noVol, `\`)
	destRel := filepath.Join("files", strings.ReplaceAll(vol, ":", ""), noVol)
	destFull := filepath.Join(backupDir, destRel)

	if err := os.MkdirAll(filepath.Dir(destFull), 0755); err != nil {
		return err
	}

	hash, err := copyFileAndHash(srcPath, destFull)
	if err != nil {
		return err
	}

	manifest.Files = append(manifest.Files, FileBackupItem{
		OriginalPath: srcPath,
		BackupPath:   destRel,
		Size:         fi.Size(),
		SHA256:       hash,
	})
	return nil
}

func copyFileAndHash(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer out.Close()

	h := sha256.New()
	mw := io.MultiWriter(out, h)
	if _, err := io.Copy(mw, in); err != nil {
		return "", err
	}

	if err := out.Sync(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func exportCertificateScope(storeName, thumbprint, destFile string, scope *bool) error {
	scopes := []bool{true, false}
	if scope != nil {
		scopes = []bool{*scope}
	}
	for _, localMachine := range scopes {
		hStore, err := openSystemRootStore(localMachine)
		if err != nil || hStore == 0 {
			continue
		}

		var prev *windows.CertContext
		found := false
		for {
			certContext, err := windows.CertEnumCertificatesInStore(hStore, prev)
			if err != nil || certContext == nil {
				break
			}
			prev = certContext

			certBytes := unsafe.Slice(certContext.EncodedCert, certContext.Length)
			h := sha1.New()
			h.Write(certBytes)
			currThumb := hex.EncodeToString(h.Sum(nil))

			if strings.EqualFold(currThumb, thumbprint) {
				if err := os.WriteFile(destFile, certBytes, 0600); err != nil {
					_ = windows.CertFreeCertificateContext(certContext)
					_ = windows.CertCloseStore(hStore, windows.CERT_CLOSE_STORE_FORCE_FLAG)
					return err
				}
				_ = windows.CertFreeCertificateContext(certContext)
				found = true
				break
			}
		}

		_ = windows.CertCloseStore(hStore, windows.CERT_CLOSE_STORE_FORCE_FLAG)
		if found {
			return nil
		}
	}

	return fmt.Errorf("未找到指纹为 %s 的证书", thumbprint)
}
