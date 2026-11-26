// 判据取自 Clear_aTrust（MIT License, Copyright (c) 2026 FlyingFishBall）

package service

import (
	"strings"
)

// SangforKeywords 包含匹配 Sangfor / aTrust / EasyConnect 组件的关键字
var SangforKeywords = []string{
	"sangfor",
	"深信服",
	"atrust",
	"easyconnect",
	"easconnect",
	"eaio",
	"nac_monitor",
	"nac_agent",
	"sdpvnic",
	"atrustxtun",
	"sfremovecallback",
	"sangforhelpertool",
	"sangforvnic",
	"sangfortcpdrv",
	"sangfordnsdrv",
	"sangfornsp",
	"sangforlsp",
	"sangforbho",
	"sangforserviceclient",
	"sangforpromoteservice",
	"sangforupdate",
	"sjobber",
	"sangforcore",
	"sangforcdc",
	"sangforl3vpn",
	"sangforsddn",
	"sangforwebuictrl",
	"sangforrapp",
	"ingressmgr",
	"ingress manager",
	"ingress_service",
	"windivert",
}

// ExcludedProcesses 自身与受保护进程，绝对不得终止
var ExcludedProcesses = []string{
	"connect-hub.exe",
	"connect-hub-capture.exe",
	"connect-hub-cleanup.exe",
	"connect-hub-worker.exe",
	"connect-hub-relay.exe",
	"connect-hub-guard.exe",
}

// ExcludedTasks 受保护的系统计划任务
var ExcludedTasks = []string{
	"aTrustHubTUN",
}

// KnownServices 已知的服务名前缀或完整名
var KnownServices = []string{
	"SangforServiceClient",
	"SangforPromoteService",
	"SangforUpdate",
	"SJobber",
	"SangforPW",
	"SangforPWEx",
	"SangforSP",
	"eaio_service",
	"nac_monitor",
	"IngressMgr",
	"SangforTcpDrv",
	"SangforDnsDrv",
	"SangforVnic",
	"SdpVnic",
	"aTrustXtun",
	"SfRemoveCallback",
	"WinDivert",
}

// KnownDrivers 已知驱动文件名
var KnownDrivers = []string{
	"SangforVnic.sys",
	"SangforTcpDrv.sys",
	"SangforDnsDrv.sys",
	"WfpDrv.sys",
	"WfpDrvX64.sys",
	"DnsDrv.sys",
	"DnsDrvx64.sys",
	"SdpVnic.sys",
	"aTrustXtun.sys",
	"SfRemoveCallback.sys",
	"WinDivert.sys",
	"WinDivert64.sys",
}

// KnownProgIDs 已知的 COM / BHO ProgID
var KnownProgIDs = []string{
	"SangforBHO.SangforHelper",
	"SangforBHO.SangforIEBHO",
	"SangforCDC.Server",
	"SangforCore.SangforCoreCom",
	"SangforL3Vpn.L3Vpn",
	"SangforSddn.Sddn",
	"SangforWebUICtrl.1",
}

// FixedRegistryKeys 固定扫描的注册表根键
var FixedRegistryKeys = []string{
	`SOFTWARE\WOW6432Node\Sangfor`,
	`SOFTWARE\Sangfor`,
	`SYSTEM\CurrentControlSet\Services\EventLog\Application\Ingress Manager`,
}

// MatchesKeyword 检查字符串（不区分大小写）是否包含任意 Sangfor 关键字
func MatchesKeyword(s string) bool {
	lower := strings.ToLower(s)
	for _, kw := range SangforKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
