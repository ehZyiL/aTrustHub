//go:build windows

package service

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func openSystemRootStore(localMachine bool) (windows.Handle, error) {
	return openSystemRootStoreWithMode(localMachine, true)
}

func openSystemRootStoreWithMode(localMachine bool, readOnly bool) (windows.Handle, error) {
	storeName, err := windows.UTF16PtrFromString("Root")
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_CURRENT_USER)
	if localMachine {
		flags = uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE)
	}
	if readOnly {
		flags |= uint32(windows.CERT_STORE_READONLY_FLAG)
	}

	hStore, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		flags,
		uintptr(unsafe.Pointer(storeName)),
	)
	if err != nil {
		return 0, err
	}
	return hStore, nil
}

// ScanOptions 扫描控制参数
type ScanOptions struct {
	ForceElevateCheck bool
	Context           context.Context
}

// Scan 执行全项扫描并产出 Plan
func Scan(opts ScanOptions) (*Plan, error) {
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	elevated := windows.GetCurrentProcessToken().IsElevated()

	plan := &Plan{
		Version:                          2,
		ScannedAt:                        time.Now(),
		Elevated:                         elevated,
		RequiresElevationForCompleteScan: !elevated,
		Installed:                        make([]InstalledApp, 0),
		Findings:                         make([]Finding, 0),
		Warnings:                         make([]string, 0),
	}

	if !elevated {
		plan.Warnings = append(plan.Warnings, "当前以普通用户权限运行，部分受系统特权保护的驱动、服务与证书可能受限，清理时将自动进行提权复核")
	}

	// 1. 扫描已安装官方客户端（引导卸载用）
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanInstalledApps(plan)

	// 2. 扫描服务与驱动
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanServicesAndDrivers(plan)

	// 3. 扫描正在运行的进程
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanProcesses(plan)

	// 4. 扫描注册表固定键与 COM
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanRegistry(plan)

	// 5. 扫描 Winsock 目录
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanWinsock(plan)

	// 6. 扫描虚拟网卡设备
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanNetAdapters(plan)

	// 7. 扫描根证书（LocalMachine + CurrentUser）
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanCertificates(plan)

	// 8. 扫描文件与目录残留
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanFileSystem(plan)

	// 9. 扫描虚拟盘 DOS Devices
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanDosDevices(plan)

	// 10. 扫描浏览器策略
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanBrowserPolicies(plan)

	// 11. 扫描 DriverStore 驱动包
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanDriverPackages(ctx, plan)

	// 12. 扫描 %TEMP% 与解包临时文件
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanTempResiduals(plan)

	// 13. 扫描 COM 与 BHO 插件
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanComAndBHO(plan)

	// 14. 扫描防火墙残留规则
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scanFirewallRules(plan)

	return plan, ctx.Err()
}

func scanInstalledApps(plan *Plan) {
	uninstallRoots := []struct {
		root registry.Key
		view uint32
		name string
	}{
		{registry.LOCAL_MACHINE, registry.WOW64_32KEY, "HKLM_32"},
		{registry.LOCAL_MACHINE, registry.WOW64_64KEY, "HKLM_64"},
		{registry.CURRENT_USER, 0, "HKCU"},
	}

	subKeyPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

	for _, entry := range uninstallRoots {
		access := uint32(registry.ENUMERATE_SUB_KEYS | registry.QUERY_VALUE)
		if entry.view != 0 {
			access |= entry.view
		}

		k, err := registry.OpenKey(entry.root, subKeyPath, access)
		if err != nil {
			continue
		}

		subNames, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, sub := range subNames {
			sk, err := registry.OpenKey(entry.root, subKeyPath+`\`+sub, access)
			if err != nil {
				continue
			}

			dispName, _, _ := sk.GetStringValue("DisplayName")
			publisher, _, _ := sk.GetStringValue("Publisher")
			uninst, _, _ := sk.GetStringValue("UninstallString")
			sk.Close()

			matched, name := ClassifyInstalledApp(sub, dispName, publisher, uninst)
			if matched && uninst != "" {
				plan.Installed = append(plan.Installed, InstalledApp{
					Name:            name,
					UninstallString: uninst,
					Hive:            entry.name,
					Key:             subKeyPath + `\` + sub,
				})
			}
		}
	}
}

func scanServicesAndDrivers(plan *Plan) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, name := range names {
		isKnown := false
		for _, ks := range KnownServices {
			if strings.EqualFold(name, ks) || strings.HasPrefix(strings.ToLower(name), strings.ToLower(ks)) {
				isKnown = true
				break
			}
		}

		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.READ)
		if err != nil {
			continue
		}

		imagePath, _, _ := sk.GetStringValue("ImagePath")
		svcType, _, _ := sk.GetIntegerValue("Type")
		sk.Close()

		if isKnown || MatchesKeyword(name) || MatchesKeyword(imagePath) {
			isDriver := (svcType == 1 || svcType == 2 || strings.HasSuffix(strings.ToLower(imagePath), ".sys"))
			risk := RiskNormal
			title := name
			detail := "服务"
			action := ActionDeleteService

			if strings.EqualFold(name, "WinDivert") {
				risk = RiskDeep
				detail = "驱动 · 可能被其他网络工具共用"
			} else if isDriver {
				detail = "内核/网络驱动"
			}

			plan.Findings = append(plan.Findings, Finding{
				ID:       fmt.Sprintf("svc:%s", name),
				Group:    "service",
				Family:   detectFamily(name + " " + imagePath),
				Title:    title,
				Detail:   detail,
				Risk:     risk,
				Action:   action,
				Params:   map[string]interface{}{"name": name, "isDriver": isDriver},
				Selected: risk == RiskNormal,
			})
		}
	}
}

func scanProcesses(plan *Plan) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var proc windows.ProcessEntry32
	proc.Size = uint32(unsafe.Sizeof(proc))

	if err := windows.Process32First(snapshot, &proc); err != nil {
		return
	}

	foundMap := make(map[string]bool)

	for {
		name := windows.UTF16ToString(proc.ExeFile[:])
		lowerName := strings.ToLower(name)

		isExcluded := false
		for _, exc := range ExcludedProcesses {
			if strings.EqualFold(lowerName, strings.ToLower(exc)) {
				isExcluded = true
				break
			}
		}

		if !isExcluded && MatchesKeyword(name) {
			if !foundMap[lowerName] {
				foundMap[lowerName] = true
				plan.Findings = append(plan.Findings, Finding{
					ID:       fmt.Sprintf("proc:%s", name),
					Group:    "process",
					Family:   detectFamily(name),
					Title:    name,
					Detail:   fmt.Sprintf("运行中的进程 (PID: %d)", proc.ProcessID),
					Risk:     RiskNormal,
					Action:   ActionKillProcess,
					Params:   map[string]interface{}{"image": name},
					Selected: true,
				})
			}
		}

		if err := windows.Process32Next(snapshot, &proc); err != nil {
			break
		}
	}
}

func scanRegistry(plan *Plan) {
	for _, fk := range FixedRegistryKeys {
		for _, view := range []struct {
			flag uint32
			name string
		}{
			{registry.WOW64_32KEY, "32"},
			{registry.WOW64_64KEY, "64"},
		} {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, fk, registry.READ|view.flag)
			if err == nil {
				k.Close()
				plan.Findings = append(plan.Findings, Finding{
					ID:       fmt.Sprintf("reg:HKLM_%s\\%s", view.name, fk),
					Group:    "registry",
					Title:    fmt.Sprintf(`HKLM (%s位) \%s`, view.name, fk),
					Detail:   "配置注册表树残留",
					Risk:     RiskNormal,
					Action:   ActionDeleteRegistry,
					Params:   map[string]interface{}{"hive": "HKLM", "key": fk, "view": view.name},
					Selected: true,
				})
			}
		}
	}

	// HKCU
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Sangfor`, registry.READ)
	if err == nil {
		k.Close()
		plan.Findings = append(plan.Findings, Finding{
			ID:       `reg:HKCU\SOFTWARE\Sangfor`,
			Group:    "registry",
			Title:    `HKCU\SOFTWARE\Sangfor`,
			Detail:   "用户配置注册表树残留",
			Risk:     RiskNormal,
			Action:   ActionDeleteRegistry,
			Params:   map[string]interface{}{"hive": "HKCU", "key": `SOFTWARE\Sangfor`},
			Selected: true,
		})
	}
}

func scanWinsock(plan *Plan) {
	catalogBases := []string{
		`SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries`,
		`SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries`,
	}

	for _, base := range catalogBases {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
		if err != nil {
			continue
		}
		subKeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}

		for _, sub := range subKeys {
			entryKeyPath := base + `\` + sub
			ek, err := registry.OpenKey(registry.LOCAL_MACHINE, entryKeyPath, registry.READ)
			if err != nil {
				continue
			}

			libPath, _, _ := ek.GetStringValue("LibraryPath")
			protoName, _, _ := ek.GetStringValue("ProtocolName")
			dispString, _, _ := ek.GetStringValue("DisplayString")
			providerIDBytes, _, _ := ek.GetBinaryValue("ProviderId")
			ek.Close()

			if ClassifyWinsockEntry(libPath) || ClassifyWinsockEntry(protoName) || ClassifyWinsockEntry(dispString) {
				isNSP := strings.Contains(base, "NameSpace")
				plan.Findings = append(plan.Findings, Finding{
					ID:     fmt.Sprintf("winsock:%s", sub),
					Group:  "winsock",
					Family: "ec",
					Title:  fmt.Sprintf("Winsock Provider: %s", sub),
					Detail: fmt.Sprintf("%s (%s)", protoName+dispString, libPath),
					Risk:   RiskNormal,
					Action: ActionUninstallWinsockProv,
					Params: map[string]interface{}{
						"keyPath":     entryKeyPath,
						"isNameSpace": isNSP,
						"providerId":  hex.EncodeToString(providerIDBytes),
						"libraryPath": libPath,
					},
					Selected: true,
				})
			}
		}
	}
}

func scanNetAdapters(plan *Plan) {
	classKey := `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, classKey, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()

	subs, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, sub := range subs {
		if len(sub) != 4 {
			continue
		}
		sk, err := registry.OpenKey(registry.LOCAL_MACHINE, classKey+`\`+sub, registry.READ)
		if err != nil {
			continue
		}

		driverDesc, _, _ := sk.GetStringValue("DriverDesc")
		netCfgInstanceId, _, _ := sk.GetStringValue("NetCfgInstanceId")
		matchingDevID, _, _ := sk.GetStringValue("MatchingDeviceId")
		sk.Close()

		if MatchesKeyword(driverDesc) || MatchesKeyword(matchingDevID) {
			// NetCfgInstanceId is a network interface GUID, not the PnP device
			// instance ID required by pnputil /remove-device.
			instanceID, err := networkDeviceInstanceID(netCfgInstanceId)
			if err != nil {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("无法确定网卡设备实例，保留 %s: %v", driverDesc, err))
				continue
			}
			plan.Findings = append(plan.Findings, Finding{
				ID:     fmt.Sprintf("adapter:%s", sub),
				Group:  "netadapter",
				Family: "ec",
				Title:  fmt.Sprintf("虚拟网卡: %s", driverDesc),
				Detail: fmt.Sprintf("设备条目 (%s, ID: %s)", sub, netCfgInstanceId),
				Risk:   RiskDeep,
				Action: ActionRemoveDevice,
				Params: map[string]interface{}{
					"instanceId": instanceID,
					"driverDesc": driverDesc,
					"subKey":     classKey + `\` + sub,
				},
				Selected: false,
			})
		}
	}
}

func networkDeviceInstanceID(interfaceGUID string) (string, error) {
	if _, err := windows.GUIDFromString(interfaceGUID); err != nil {
		return "", err
	}
	path := `SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\` + interfaceGUID + `\Connection`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	id, _, err := k.GetStringValue("PnpInstanceID")
	if err != nil {
		return "", err
	}
	if !strings.Contains(id, `\`) {
		return "", fmt.Errorf("无效的 PnP 设备实例")
	}
	return id, nil
}

func scanCertificates(plan *Plan) {
	for _, localMachine := range []bool{true, false} {
		hStore, err := openSystemRootStore(localMachine)
		if err != nil || hStore == 0 {
			continue
		}

		storeDesc := "LocalMachine"
		if !localMachine {
			storeDesc = "CurrentUser"
		}

		var prev *windows.CertContext
		for {
			certContext, err := windows.CertEnumCertificatesInStore(hStore, prev)
			if err != nil || certContext == nil {
				break
			}
			prev = certContext

			// 获取 Subject
			buf := make([]uint16, 256)
			windows.CertGetNameString(
				certContext,
				windows.CERT_NAME_SIMPLE_DISPLAY_TYPE,
				0,
				nil,
				&buf[0],
				uint32(len(buf)),
			)
			subject := windows.UTF16ToString(buf)

			// 获取 Issuer
			bufIssuer := make([]uint16, 256)
			windows.CertGetNameString(
				certContext,
				windows.CERT_NAME_SIMPLE_DISPLAY_TYPE,
				windows.CERT_NAME_ISSUER_FLAG,
				nil,
				&bufIssuer[0],
				uint32(len(bufIssuer)),
			)
			issuer := windows.UTF16ToString(bufIssuer)

			if MatchesKeyword(subject) || MatchesKeyword(issuer) {
				certBytes := unsafe.Slice(certContext.EncodedCert, certContext.Length)
				h := sha1.New()
				h.Write(certBytes)
				thumbprint := hex.EncodeToString(h.Sum(nil))

				plan.Findings = append(plan.Findings, Finding{
					ID:     fmt.Sprintf("cert:%s_%s", storeDesc, thumbprint),
					Group:  "cert",
					Title:  fmt.Sprintf("根证书: %s", subject),
					Detail: fmt.Sprintf("存储: %s, 签发者: %s (指纹: %s)", storeDesc, issuer, thumbprint),
					Risk:   RiskNormal,
					Action: ActionDeleteCert,
					Params: map[string]interface{}{
						"store":        "Root",
						"localMachine": localMachine,
						"thumbprint":   thumbprint,
						"subject":      subject,
					},
					Selected: true,
				})
			}
		}
		_ = windows.CertCloseStore(hStore, windows.CERT_CLOSE_STORE_FORCE_FLAG)
	}
}

func scanFileSystem(plan *Plan) {
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	if programFilesX86 == "" {
		programFilesX86 = `C:\Program Files (x86)`
	}
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		programFiles = `C:\Program Files`
	}
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")
	programData := os.Getenv("ProgramData")
	tempDir := os.TempDir()

	candidateDirs := []string{
		filepath.Join(programFilesX86, "Sangfor"),
		filepath.Join(programFiles, "Sangfor"),
		filepath.Join(appData, "Sangfor"),
		filepath.Join(localAppData, "Sangfor"),
		filepath.Join(programData, "Sangfor"),
		filepath.Join(tempDir, "SangforPAC"),
	}

	for _, dir := range candidateDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			plan.Findings = append(plan.Findings, Finding{
				ID:     fmt.Sprintf("dir:%s", dir),
				Group:  "file",
				Family: detectFamily(dir),
				Title:  fmt.Sprintf("目录残留: %s", filepath.Base(dir)),
				Detail: dir,
				Risk:   RiskNormal,
				Action: ActionDeletePath,
				Params: map[string]interface{}{
					"path":  dir,
					"isDir": true,
				},
				Selected: true,
			})
		}
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	driverDir := filepath.Join(systemRoot, "System32", "drivers")
	for _, drv := range KnownDrivers {
		drvPath := filepath.Join(driverDir, drv)
		if _, err := os.Stat(drvPath); err == nil {
			plan.Findings = append(plan.Findings, Finding{
				ID:     fmt.Sprintf("file:%s", drvPath),
				Group:  "file",
				Family: detectFamily(drv),
				Title:  fmt.Sprintf("驱动文件: %s", drv),
				Detail: drvPath,
				Risk:   RiskNormal,
				Action: ActionDeletePath,
				Params: map[string]interface{}{
					"path":  drvPath,
					"isDir": false,
				},
				Selected: true,
			})
		}
	}
}

func scanDosDevices(plan *Plan) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices`, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}

	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}

		classification := ClassifyDosDevice(name, val)
		if classification == "suspicious" {
			plan.Findings = append(plan.Findings, Finding{
				ID:     fmt.Sprintf("dos:%s", name),
				Group:  "virtualdrive",
				Title:  fmt.Sprintf("虚拟盘符映射: %s", name),
				Detail: fmt.Sprintf("指向: %s", val),
				Risk:   RiskNormal,
				Action: ActionClearDosDevice,
				Params: map[string]interface{}{
					"letter": name,
					"target": val,
				},
				Selected: true,
			})
		}
	}
}

func scanBrowserPolicies(plan *Plan) {
	policyPaths := []string{
		`SOFTWARE\Policies\Google\Chrome`,
		`SOFTWARE\Policies\Microsoft\Edge`,
	}

	for _, p := range policyPaths {
		for _, view := range []struct {
			flag uint32
			name string
		}{
			{registry.WOW64_32KEY, "32"},
			{registry.WOW64_64KEY, "64"},
		} {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.READ|view.flag)
			if err != nil {
				continue
			}

			valNames, _ := k.ReadValueNames(-1)
			for _, vn := range valNames {
				valData, _, _ := k.GetStringValue(vn)
				if ClassifyBrowserPolicyValue(vn, valData) {
					plan.Findings = append(plan.Findings, Finding{
						ID:     fmt.Sprintf("policy:%s\\%s", p, vn),
						Group:  "browserpolicy",
						Title:  fmt.Sprintf("浏览器策略: %s", vn),
						Detail: fmt.Sprintf("%s = %s", p, valData),
						Risk:   RiskDeep,
						Action: ActionDeletePolicyValue,
						Params: map[string]interface{}{
							"hive":  "HKLM",
							"view":  view.name,
							"key":   p,
							"value": vn,
						},
						Selected: false,
					})
				}
			}
			k.Close()
		}
	}
}

func scanDriverPackages(ctx context.Context, plan *Plan) {
	cmd := exec.CommandContext(ctx, "pnputil.exe", "/enum-drivers")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")
	var currentPublished string
	var currentOriginal string
	var currentProvider string

	flushPackage := func() {
		if currentPublished != "" {
			if MatchesKeyword(currentOriginal) || MatchesKeyword(currentProvider) {
				plan.Findings = append(plan.Findings, Finding{
					ID:       fmt.Sprintf("drvpkg:%s", currentPublished),
					Group:    "driverpackage",
					Family:   "ec",
					Title:    fmt.Sprintf("驱动包: %s", currentPublished),
					Detail:   fmt.Sprintf("原始驱动: %s (%s)", currentOriginal, currentProvider),
					Risk:     RiskDeep,
					Action:   ActionDeleteDriverPackage,
					Params:   map[string]interface{}{"inf": currentPublished},
					Selected: false,
				})
			}
		}
		currentPublished = ""
		currentOriginal = ""
		currentProvider = ""
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "published name") || strings.HasPrefix(line, "发布名称") {
			flushPackage()
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				currentPublished = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "original name") || strings.HasPrefix(line, "原始名称") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				currentOriginal = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(lower, "provider name") || strings.HasPrefix(line, "提供程序名称") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				currentProvider = strings.TrimSpace(parts[1])
			}
		}
	}
	flushPackage()
}

func scanTempResiduals(plan *Plan) {
	tempDir := os.TempDir()
	entries, err := os.ReadDir(tempDir)
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			lower := strings.ToLower(name)
			isMatch := false

			// 匹配 1_*Installer.exe, 1_Sangfor*.CAB, SangforUD.exe
			if strings.HasPrefix(lower, "1_") && (strings.Contains(lower, "sangfor") || strings.HasSuffix(lower, "installer.exe") || strings.HasSuffix(lower, ".cab")) {
				isMatch = true
			} else if strings.EqualFold(name, "SangforUD.exe") {
				isMatch = true
			}

			if isMatch {
				p := filepath.Join(tempDir, name)
				plan.Findings = append(plan.Findings, Finding{
					ID:       fmt.Sprintf("temp:%s", name),
					Group:    "file",
					Family:   "ec",
					Title:    fmt.Sprintf("临时解包残留: %s", name),
					Detail:   p,
					Risk:     RiskNormal,
					Action:   ActionDeletePath,
					Params:   map[string]interface{}{"path": p, "isDir": e.IsDir()},
					Selected: true,
				})
			}
		}
	}

	// 扫描 %APPDATA%\EasyConnect_*
	appData := os.Getenv("APPDATA")
	if appData != "" {
		if adEntries, err := os.ReadDir(appData); err == nil {
			for _, e := range adEntries {
				if e.IsDir() && strings.HasPrefix(strings.ToLower(e.Name()), "easyconnect_") {
					p := filepath.Join(appData, e.Name())
					plan.Findings = append(plan.Findings, Finding{
						ID:       fmt.Sprintf("temp:%s", e.Name()),
						Group:    "file",
						Family:   "ec",
						Title:    fmt.Sprintf("解包运行目录: %s", e.Name()),
						Detail:   p,
						Risk:     RiskNormal,
						Action:   ActionDeletePath,
						Params:   map[string]interface{}{"path": p, "isDir": true},
						Selected: true,
					})
				}
			}
		}
	}
}

func scanComAndBHO(plan *Plan) {
	// 1. 扫描已知 ProgID
	for _, progID := range KnownProgIDs {
		keyPath := `SOFTWARE\Classes\` + progID
		for _, view := range []struct {
			flag uint32
			name string
		}{
			{registry.WOW64_32KEY, "32"},
			{registry.WOW64_64KEY, "64"},
		} {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ|view.flag)
			if err == nil {
				k.Close()
				plan.Findings = append(plan.Findings, Finding{
					ID:       fmt.Sprintf("com:%s_%s", progID, view.name),
					Group:    "bho",
					Family:   "ec",
					Title:    fmt.Sprintf("COM ProgID (%s位): %s", view.name, progID),
					Detail:   keyPath,
					Risk:     RiskNormal,
					Action:   ActionDeleteRegistry,
					Params:   map[string]interface{}{"hive": "HKLM", "key": keyPath, "view": view.name},
					Selected: true,
				})
			}
		}
	}

	// 2. 扫描 Browser Helper Objects
	bhoPath := `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
	for _, view := range []struct {
		flag uint32
		name string
	}{
		{registry.WOW64_32KEY, "32"},
		{registry.WOW64_64KEY, "64"},
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, bhoPath, registry.READ|view.flag)
		if err != nil {
			continue
		}
		clsids, _ := k.ReadSubKeyNames(-1)
		k.Close()

		for _, clsid := range clsids {
			// 查询该 CLSID 对应的 InprocServer32
			clsidKey := fmt.Sprintf(`SOFTWARE\Classes\CLSID\%s\InprocServer32`, clsid)
			ck, err := registry.OpenKey(registry.LOCAL_MACHINE, clsidKey, registry.READ|view.flag)
			if err != nil {
				continue
			}
			dllPath, _, _ := ck.GetStringValue("")
			ck.Close()

			if MatchesKeyword(dllPath) {
				fullBhoKey := bhoPath + `\` + clsid
				plan.Findings = append(plan.Findings, Finding{
					ID:       fmt.Sprintf("bho:%s_%s", clsid, view.name),
					Group:    "bho",
					Family:   "ec",
					Title:    fmt.Sprintf("浏览器插件 BHO (%s位)", view.name),
					Detail:   fmt.Sprintf("%s (%s)", clsid, dllPath),
					Risk:     RiskNormal,
					Action:   ActionDeleteRegistry,
					Params:   map[string]interface{}{"hive": "HKLM", "key": fullBhoKey, "view": view.name},
					Selected: true,
				})
			}
		}
	}
}

func scanFirewallRules(plan *Plan) {
	fwPath := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, fwPath, registry.READ)
	if err != nil {
		return
	}
	defer k.Close()

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}

	for _, name := range names {
		val, _, err := k.GetStringValue(name)
		if err != nil {
			continue
		}

		lowerVal := strings.ToLower(val)
		lowerName := strings.ToLower(name)

		// 严格排除自身程序（connect-hub、connect-hub-cleanup、connect-hub-capture 等）
		if strings.Contains(lowerVal, "connect-hub") || strings.Contains(lowerName, "connect-hub") {
			continue
		}
		isSelf := false
		for _, excl := range ExcludedProcesses {
			if strings.Contains(lowerVal, strings.ToLower(excl)) || strings.Contains(lowerName, strings.ToLower(excl)) {
				isSelf = true
				break
			}
		}
		if isSelf {
			continue
		}

		if MatchesKeyword(val) || MatchesKeyword(name) {
			plan.Findings = append(plan.Findings, Finding{
				ID:     fmt.Sprintf("fw:%s", name),
				Group:  "firewall",
				Family: detectFamily(val),
				Title:  fmt.Sprintf("防火墙残留规则: %s", name),
				Detail: val,
				Risk:   RiskNormal,
				Action: ActionDeletePolicyValue,
				Params: map[string]interface{}{
					"hive":  "HKLM",
					"key":   fwPath,
					"value": name,
				},
				Selected: true,
			})
		}
	}
}

func detectFamily(s string) string {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "atrust") || strings.Contains(lower, "ingress") || strings.Contains(lower, "eaio") {
		return "atrust"
	}
	return "ec"
}
