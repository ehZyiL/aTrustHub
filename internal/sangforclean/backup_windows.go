//go:build windows

package sangforclean

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DefaultBackupRootDir 获取默认备份根目录
func DefaultBackupRootDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = os.TempDir()
	}
	return filepath.Join(appData, "ConnectHub", "cleanup", "backups")
}

// CreateBackup 执行全量快照备份并输出 BackupManifest
func CreateBackup(plan *Plan, backupRootDir string) (*BackupManifest, error) {
	if backupRootDir == "" {
		backupRootDir = DefaultBackupRootDir()
	}

	backupID := time.Now().Format("20060102-150405")
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
		if !f.Selected {
			continue
		}

		if f.Action == ActionDeleteRegistry {
			hive, _ := f.Params["hive"].(string)
			key, _ := f.Params["key"].(string)
			view, _ := f.Params["view"].(string)

			if hive != "" && key != "" {
				fullKey := hive + `\` + key
				safeName := strings.ReplaceAll(strings.ReplaceAll(fullKey, `\`, `_`), `:`, `_`)
				backupRel := filepath.Join("registry", safeName+".reg")
				backupDest := filepath.Join(backupDir, backupRel)

				cmd := exec.Command("reg.exe", "export", fullKey, backupDest, "/y")
				cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
				_ = cmd.Run()

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

			_ = backupFileOrDir(path, fileDir, backupDir, manifest)
		} else if f.Action == ActionDeleteCert {
			thumbprint, _ := f.Params["thumbprint"].(string)
			subject, _ := f.Params["subject"].(string)
			store, _ := f.Params["store"].(string)

			if thumbprint != "" {
				certRel := filepath.Join("certs", thumbprint+".cer")
				certDest := filepath.Join(backupDir, certRel)
				if err := exportCertificate(store, thumbprint, certDest); err == nil {
					manifest.Certificates = append(manifest.Certificates, CertBackupItem{
						Store:      store,
						Thumbprint: thumbprint,
						Subject:    subject,
						BackupFile: certRel,
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
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		return nil, fmt.Errorf("保存 manifest 失败: %w", err)
	}

	return manifest, nil
}

func backupFileOrDir(srcPath, fileBackupRoot, backupDir string, manifest *BackupManifest) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}

	if fi.IsDir() {
		return filepath.Walk(srcPath, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
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
		return nil
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

	return hex.EncodeToString(h.Sum(nil)), nil
}

func exportCertificate(storeName, thumbprint, destFile string) error {
	for _, localMachine := range []bool{true, false} {
		hStore, err := openSystemRootStore(localMachine)
		if err != nil || hStore == 0 {
			continue
		}

		var pCertContext uintptr
		found := false
		for {
			pCertContext, _, _ = procCertEnumCertificatesInStore.Call(hStore, pCertContext)
			if pCertContext == 0 {
				break
			}

			ctx := (*windows.CertContext)(unsafe.Pointer(pCertContext))
			certBytes := unsafe.Slice(ctx.EncodedCert, ctx.Length)

			h := sha1.New()
			h.Write(certBytes)
			currThumb := hex.EncodeToString(h.Sum(nil))

			if strings.EqualFold(currThumb, thumbprint) {
				_ = os.WriteFile(destFile, certBytes, 0644)
				procCertFreeCertificateContext.Call(pCertContext)
				found = true
				break
			}
		}

		procCertCloseStore.Call(hStore, CERT_CLOSE_STORE_FORCE_FLAG)
		if found {
			return nil
		}
	}

	return fmt.Errorf("未找到指纹为 %s 的证书", thumbprint)
}
