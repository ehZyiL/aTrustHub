//go:build windows

package sangforclean

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	procCertDeleteCertificateFromStore = modcrypt32.NewProc("CertDeleteCertificateFromStore")
)

// ApplyOptions 执行参数
type ApplyOptions struct {
	Plan          *Plan
	ReportPath    string
	OnlyIDs       []string
	SkipIDs       []string
	BackupRootDir string
}

// Apply 执行清理任务
func Apply(opts ApplyOptions) (int, error) {
	if opts.Plan == nil {
		return 2, fmt.Errorf("plan 为空")
	}

	elevated := IsElevated()

	// 1. 初始化报告写入器
	var rw *ReportWriter
	var err error
	if opts.ReportPath != "" {
		rw, err = NewReportWriter(opts.ReportPath)
		if err != nil {
			return 2, fmt.Errorf("创建报告文件失败: %w", err)
		}
		defer rw.Close()
	}

	// 2. 若在提权模式下执行，进行静默复核扫描并自动补全被权限遮蔽的特权残留
	if elevated {
		if freshPlan, err := Scan(ScanOptions{}); err == nil && freshPlan != nil {
			existingIDs := make(map[string]bool)
			for _, f := range opts.Plan.Findings {
				existingIDs[f.ID] = true
			}
			for _, freshF := range freshPlan.Findings {
				if !existingIDs[freshF.ID] {
					opts.Plan.Findings = append(opts.Plan.Findings, freshF)
				}
			}
		}
	}

	// 3. 应用 --only / --skip 过滤，并在备份前写回 Selected 状态（保证执行项 100% 纳入备份）
	onlyMap := make(map[string]bool)
	for _, id := range opts.OnlyIDs {
		onlyMap[strings.TrimSpace(id)] = true
	}
	skipMap := make(map[string]bool)
	for _, id := range opts.SkipIDs {
		skipMap[strings.TrimSpace(id)] = true
	}

	selectedFindings := make([]Finding, 0)
	for i := range opts.Plan.Findings {
		f := &opts.Plan.Findings[i]
		if len(onlyMap) > 0 {
			f.Selected = onlyMap[f.ID]
		}
		if skipMap[f.ID] {
			f.Selected = false
		}
		if f.Selected {
			selectedFindings = append(selectedFindings, *f)
		}
	}

	// 4. 执行全量快照备份（零数据损失安全保障）
	manifest, err := CreateBackup(opts.Plan, opts.BackupRootDir)
	if err != nil {
		if rw != nil {
			_ = rw.WriteEvent(ReportEvent{
				Event:   "end",
				Status:  StatusFailed,
				Message: fmt.Sprintf("创建备份失败，安全终止: %v", err),
				Exit:    2,
			})
		}
		return 2, fmt.Errorf("清理前全量备份失败: %w", err)
	}

	manifestPath := filepath.Join(opts.BackupRootDir, manifest.BackupID, "manifest.json")
	if opts.BackupRootDir == "" {
		manifestPath = filepath.Join(DefaultBackupRootDir(), manifest.BackupID, "manifest.json")
	}

	if rw != nil {
		_ = rw.WriteEvent(ReportEvent{
			Event:          "start",
			Total:          len(selectedFindings),
			Elevated:       elevated,
			BackupID:       manifest.BackupID,
			BackupManifest: manifestPath,
		})
		_ = rw.WriteEvent(ReportEvent{
			Event:   "backup",
			Status:  StatusOk,
			Message: fmt.Sprintf("已完成清理前快照备份 (ID: %s)", manifest.BackupID),
		})
	}

	okCount := 0
	failedCount := 0
	rebootCount := 0
	skippedCount := 0

	// 5. 按依赖释放顺序分阶段执行动作
	// Phase A: kill-process
	for _, f := range selectedFindings {
		if f.Action == ActionKillProcess {
			status, msg := executeKillProcess(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		}
	}

	// Phase B: delete-service
	for _, f := range selectedFindings {
		if f.Action == ActionDeleteService {
			status, msg := executeDeleteService(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		}
	}

	// Phase C: remove-device & uninstall-winsock
	for _, f := range selectedFindings {
		if f.Action == ActionRemoveDevice {
			status, msg := executeRemoveDevice(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		} else if f.Action == ActionUninstallWinsockProv {
			status, msg := executeUninstallWinsock(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		}
	}

	// Phase D: delete-registry, delete-cert, delete-policy-value, clear-dos-device, delete-driver-package
	for _, f := range selectedFindings {
		switch f.Action {
		case ActionDeleteRegistry:
			status, msg := executeDeleteRegistry(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		case ActionDeleteCert:
			status, msg := executeDeleteCert(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		case ActionDeletePolicyValue:
			status, msg := executeDeletePolicyValue(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		case ActionClearDosDevice:
			status, msg := executeClearDosDevice(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		case ActionDeleteDriverPackage:
			status, msg := executeDeleteDriverPackage(f)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		}
	}

	// Phase E: delete-path (文件最后清理)
	quarantineRoot := filepath.Join(filepath.Dir(manifestPath), "quarantine")
	for _, f := range selectedFindings {
		if f.Action == ActionDeletePath {
			status, msg := executeDeletePath(f, quarantineRoot)
			recordResult(rw, f.ID, status, msg, &okCount, &failedCount, &rebootCount, &skippedCount)
		}
	}

	// 计算最终退出码
	exitCode := 0
	if failedCount > 0 {
		exitCode = 1
	} else if rebootCount > 0 {
		exitCode = 3
	}

	if rw != nil {
		_ = rw.WriteEvent(ReportEvent{
			Event:          "end",
			Ok:             okCount,
			Failed:         failedCount,
			Reboot:         rebootCount,
			Exit:           exitCode,
			BackupManifest: manifestPath,
		})
	}

	return exitCode, nil
}

func recordResult(rw *ReportWriter, id string, status ReportStatus, msg string, ok, failed, reboot, skipped *int) {
	switch status {
	case StatusOk:
		*ok++
	case StatusFailed:
		*failed++
	case StatusReboot:
		*reboot++
	case StatusSkipped:
		*skipped++
	}

	if rw != nil {
		_ = rw.WriteEvent(ReportEvent{
			Event:   "item",
			ID:      id,
			Status:  status,
			Message: msg,
		})
	}
}

func executeKillProcess(f Finding) (ReportStatus, string) {
	image, _ := f.Params["image"].(string)
	if image == "" {
		return StatusSkipped, "缺少进程映像参数"
	}

	cmd := exec.Command("taskkill.exe", "/F", "/IM", image)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	return StatusOk, "已尝试终止进程: " + image
}

func executeDeleteService(f Finding) (ReportStatus, string) {
	name, _ := f.Params["name"].(string)
	isDriver, _ := f.Params["isDriver"].(bool)
	if name == "" {
		return StatusSkipped, "缺少服务名"
	}

	// 1. 尝试停止服务
	stopCmd := exec.Command("sc.exe", "stop", name)
	stopCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = stopCmd.Run()

	// 2. 尝试删除服务
	delCmd := exec.Command("sc.exe", "delete", name)
	delCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := delCmd.CombinedOutput()
	outStr := string(out)

	if err == nil {
		return StatusOk, "服务已成功删除: " + name
	}

	if strings.Contains(outStr, "1060") {
		return StatusSkipped, "服务已不存在"
	}

	if strings.Contains(outStr, "1072") || isDriver {
		return StatusReboot, "已标记删除（需重启生效）"
	}

	return StatusFailed, fmt.Sprintf("删除服务失败: %s (%v)", strings.TrimSpace(outStr), err)
}

func executeRemoveDevice(f Finding) (ReportStatus, string) {
	instanceId, _ := f.Params["instanceId"].(string)
	if instanceId == "" {
		return StatusSkipped, "缺少设备实例 ID"
	}

	cmd := exec.Command("pnputil.exe", "/remove-device", instanceId)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return StatusFailed, fmt.Sprintf("移除设备失败: %v", err)
	}
	return StatusOk, "已移除虚拟网卡设备节点"
}

func executeUninstallWinsock(f Finding) (ReportStatus, string) {
	providerId, _ := f.Params["providerId"].(string)
	isNSP, _ := f.Params["isNameSpace"].(bool)

	if err := UninstallWinsockProvider(providerId, isNSP); err != nil {
		return StatusFailed, fmt.Sprintf("卸载 Winsock Provider 失败: %v", err)
	}
	return StatusReboot, "已调用 Winsock API 卸载 Provider（需重启生效）"
}

func executeDeleteRegistry(f Finding) (ReportStatus, string) {
	hive, _ := f.Params["hive"].(string)
	key, _ := f.Params["key"].(string)
	view, _ := f.Params["view"].(string)

	if hive == "" || key == "" {
		return StatusSkipped, "缺少注册表定位参数"
	}

	fullKey := hive + `\` + key
	args := []string{"delete", fullKey, "/f"}
	if view == "32" {
		args = append(args, "/reg:32")
	} else if view == "64" {
		args = append(args, "/reg:64")
	}

	cmd := exec.Command("reg.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return StatusFailed, fmt.Sprintf("删除注册表失败: %v", err)
	}

	return StatusOk, "已删除注册表项: " + fullKey
}

func executeDeleteCert(f Finding) (ReportStatus, string) {
	storeName, _ := f.Params["store"].(string)
	thumbprint, _ := f.Params["thumbprint"].(string)

	if storeName == "" || thumbprint == "" {
		return StatusSkipped, "缺少证书指纹"
	}

	deleted := false
	for _, localMachine := range []bool{true, false} {
		hStore, err := openSystemRootStore(localMachine)
		if err != nil || hStore == 0 {
			continue
		}

		var pCertContext uintptr
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
				ret, _, _ := procCertDeleteCertificateFromStore.Call(pCertContext)
				if ret != 0 {
					deleted = true
				}
				break
			}
		}
		procCertCloseStore.Call(hStore, CERT_CLOSE_STORE_FORCE_FLAG)
	}

	if deleted {
		return StatusOk, "已精准删除根证书"
	}
	return StatusSkipped, "证书已不存在"
}

func executeDeletePolicyValue(f Finding) (ReportStatus, string) {
	hive, _ := f.Params["hive"].(string)
	key, _ := f.Params["key"].(string)
	val, _ := f.Params["value"].(string)
	view, _ := f.Params["view"].(string)

	fullKey := hive + `\` + key
	args := []string{"delete", fullKey, "/v", val, "/f"}
	if view == "32" {
		args = append(args, "/reg:32")
	} else if view == "64" {
		args = append(args, "/reg:64")
	}

	cmd := exec.Command("reg.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	return StatusOk, "已清理策略项: " + val
}

func executeClearDosDevice(f Finding) (ReportStatus, string) {
	letter, _ := f.Params["letter"].(string)
	if letter == "" {
		return StatusSkipped, "缺少盘符"
	}

	// 1. subst 卸除
	substCmd := exec.Command("subst.exe", letter, "/D")
	substCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = substCmd.Run()

	// 2. 从 Session Manager\DOS Devices 注册表删除值
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices`, registry.SET_VALUE)
	if err == nil {
		_ = k.DeleteValue(letter)
		k.Close()
	}

	return StatusOk, "已清理虚拟盘符: " + letter
}

func executeDeleteDriverPackage(f Finding) (ReportStatus, string) {
	inf, _ := f.Params["inf"].(string)
	if inf == "" {
		return StatusSkipped, "缺少 INF 名称"
	}

	cmd := exec.Command("pnputil.exe", "/delete-driver", inf, "/uninstall", "/force")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Run()
	return StatusReboot, "已调用 pnputil 删除驱动包（需重启生效）"
}

func executeDeletePath(f Finding, quarantineRoot string) (ReportStatus, string) {
	path, _ := f.Params["path"].(string)
	if path == "" {
		return StatusSkipped, "缺少路径"
	}

	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return StatusSkipped, "路径已不存在"
		}
		return StatusFailed, err.Error()
	}

	// 1. 尝试移入隔离区（同盘原子移动或跨盘 Copy+Delete）
	if quarantineRoot != "" {
		rel := filepath.Base(path) + "_" + time.Now().Format("150405")
		dest := filepath.Join(quarantineRoot, rel)
		_ = os.MkdirAll(quarantineRoot, 0755)

		if err := os.Rename(path, dest); err == nil {
			return StatusOk, "已移入隔离区: " + dest
		}

		// 跨盘卷移动支持：先 Copy 到隔离区再 Remove 原路径
		if !fi.IsDir() {
			if _, err := copyFileAndHash(path, dest); err == nil {
				if err := os.Remove(path); err == nil {
					return StatusOk, "已移入隔离区 (跨卷): " + dest
				}
			}
		}
	}

	// 2. 尝试直接物理删除
	if err := os.RemoveAll(path); err == nil {
		return StatusOk, "已删除路径: " + path
	}

	// 3. 文件被占用：收集子文件与所有中间子目录（后序逆序），注册 MoveFileEx 延迟删除
	if fi.IsDir() {
		var subDirs []string
		_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err == nil && info != nil {
				if info.IsDir() {
					if p != path {
						subDirs = append(subDirs, p)
					}
				} else {
					scheduleDelayedDelete(p)
				}
			}
			return nil
		})

		// 子目录按路径深度逆序（由深到浅），确保重启时先删空子目录再删父目录
		sort.Slice(subDirs, func(i, j int) bool {
			return len(subDirs[i]) > len(subDirs[j])
		})
		for _, d := range subDirs {
			scheduleDelayedDelete(d)
		}
	}
	scheduleDelayedDelete(path)

	return StatusReboot, "文件当前被占用，已登记为系统重启后删除"
}

func scheduleDelayedDelete(path string) {
	pW, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	_ = windows.MoveFileEx(pW, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
