//go:build windows

package sangforclean

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modcrypt32                      = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore               = modcrypt32.NewProc("CertOpenStore")
	procCertEnumCertificatesInStore = modcrypt32.NewProc("CertEnumCertificatesInStore")
	procCertCloseStore              = modcrypt32.NewProc("CertCloseStore")
	procCertGetNameStringW          = modcrypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext  = modcrypt32.NewProc("CertFreeCertificateContext")
)

const (
	CERT_STORE_PROV_SYSTEM_W        = 10
	CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
	CERT_SYSTEM_STORE_CURRENT_USER  = 0x00010000
	CERT_CLOSE_STORE_FORCE_FLAG     = 0x00000001

	CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
	CERT_NAME_ISSUER_FLAG         = 1
)

func openSystemRootStore(localMachine bool) (uintptr, error) {
	storeName, err := windows.UTF16PtrFromString("Root")
	if err != nil {
		return 0, err
	}
	flags := uintptr(CERT_SYSTEM_STORE_CURRENT_USER)
	if localMachine {
		flags = uintptr(CERT_SYSTEM_STORE_LOCAL_MACHINE)
	}

	hStore, _, err := procCertOpenStore.Call(
		CERT_STORE_PROV_SYSTEM_W,
		0,
		0,
		flags,
		uintptr(unsafe.Pointer(storeName)),
	)
	if hStore == 0 {
		return 0, err
	}
	return hStore, nil
}

// ScanOptions 扫描控制参数
type ScanOptions struct {
	ForceElevateCheck bool
}

// Scan 执行全项扫描并产出 Plan
func Scan(opts ScanOptions) (*Plan, error) {
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
	scanInstalledApps(plan)

	// 2. 扫描服务与驱动
	scanServicesAndDrivers(plan)

	// 3. 扫描正在运行的进程
	scanProcesses(plan)

	// 4. 扫描注册表固定键与 COM
	scanRegistry(plan)

	// 5. 扫描 Winsock 目录
	scanWinsock(plan)

	// 6. 扫描虚拟网卡设备
	scanNetAdapters(plan)

	// 7. 扫描根证书（LocalMachine + CurrentUser）
	scanCertificates(plan)

	// 8. 扫描文件与目录残留
	scanFileSystem(plan)

	// 9. 扫描虚拟盘 DOS Devices
	scanDosDevices(plan)

	// 10. 扫描浏览器策略
	scanBrowserPolicies(plan)

	return plan, nil
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
						"keyPath":      entryKeyPath,
						"isNameSpace":  isNSP,
						"providerId":   hex.EncodeToString(providerIDBytes),
						"libraryPath":  libPath,
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
			plan.Findings = append(plan.Findings, Finding{
				ID:     fmt.Sprintf("adapter:%s", sub),
				Group:  "netadapter",
				Family: "ec",
				Title:  fmt.Sprintf("虚拟网卡: %s", driverDesc),
				Detail: fmt.Sprintf("设备条目 (%s, ID: %s)", sub, netCfgInstanceId),
				Risk:   RiskDeep,
				Action: ActionRemoveDevice,
				Params: map[string]interface{}{
					"instanceId": netCfgInstanceId,
					"driverDesc": driverDesc,
					"subKey":     classKey + `\` + sub,
				},
				Selected: false,
			})
		}
	}
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

		var pCertContext uintptr
		for {
			pCertContext, _, _ = procCertEnumCertificatesInStore.Call(hStore, pCertContext)
			if pCertContext == 0 {
				break
			}

			// 获取 Subject
			buf := make([]uint16, 256)
			procCertGetNameStringW.Call(
				pCertContext,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				0,
				0,
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(len(buf)),
			)
			subject := windows.UTF16ToString(buf)

			// 获取 Issuer
			procCertGetNameStringW.Call(
				pCertContext,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				CERT_NAME_ISSUER_FLAG,
				0,
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(len(buf)),
			)
			issuer := windows.UTF16ToString(buf)

			if MatchesKeyword(subject) || MatchesKeyword(issuer) {
				certContext := (*windows.CertContext)(unsafe.Pointer(pCertContext))
				h := sha1.New()
				certBytes := unsafe.Slice(certContext.EncodedCert, certContext.Length)
				h.Write(certBytes)
				thumbprint := hex.EncodeToString(h.Sum(nil))

				plan.Findings = append(plan.Findings, Finding{
					ID:     fmt.Sprintf("cert:%s", thumbprint),
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
		procCertCloseStore.Call(hStore, CERT_CLOSE_STORE_FORCE_FLAG)
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

func detectFamily(s string) string {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "atrust") || strings.Contains(lower, "ingress") || strings.Contains(lower, "eaio") {
		return "atrust"
	}
	return "ec"
}
