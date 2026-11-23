// 判据取自 Clear_aTrust（MIT License, Copyright (c) 2026 FlyingFishBall）

package sangforclean

import (
	"regexp"
	"strings"
)

var dosLetterRegex = regexp.MustCompile(`^[A-Za-z]:$`)

// ClassifyDosDevice 纯函数判定 virtualdrive 盘符分类
// 返回："suspicious" (属于 Sangfor 残留且待清理), "kept" (保留用户自身映射), "manual" (底层设备路径)
func ClassifyDosDevice(letter, target string) string {
	// 1. 只处理 ^[A-Za-z]:$ 盘符条目；AUX/CON/NUL/PRN 等系统设备条目必须跳过
	if !dosLetterRegex.MatchString(letter) {
		return "kept"
	}

	upperTarget := strings.ToUpper(target)

	// 2. 目标以 \DEVICE\ 开头 → manual（原生设备路径，不自动判断）
	if strings.HasPrefix(upperTarget, `\DEVICE\`) {
		return "manual"
	}

	// 3. 目标含 Sangfor 特征 → suspicious
	if MatchesKeyword(target) {
		return "suspicious"
	}

	// 4. 其余一律保留（防止误杀普通用户自行创建但临时失效的盘符）
	return "kept"
}

// ClassifyInstalledApp 纯函数匹配已安装程序条目
// 返回：是否命中 Sangfor 客户端，以及展示名称
func ClassifyInstalledApp(keyName, displayName, publisher, uninstallString string) (bool, string) {
	name := displayName
	if name == "" {
		name = keyName
	}

	// 只要键名、Publisher 或 UninstallString 命中关键字之一即判定为 Sangfor 系列
	// （DisplayName 可能被租户白标替换，如“中原招标采购交易平台”，因此不能单靠 DisplayName 排除）
	if MatchesKeyword(keyName) || MatchesKeyword(publisher) || MatchesKeyword(uninstallString) || MatchesKeyword(displayName) {
		return true, name
	}

	return false, ""
}

// ClassifyBrowserPolicyValue 检查浏览器策略值是否包含 Sangfor 特征
func ClassifyBrowserPolicyValue(valName string, valData string) bool {
	if MatchesKeyword(valName) || MatchesKeyword(valData) {
		return true
	}
	return false
}

// ClassifyWinsockEntry 检查 Winsock 模块路径或协议描述是否为 Sangfor
func ClassifyWinsockEntry(libraryPathOrProtocol string) bool {
	return MatchesKeyword(libraryPathOrProtocol)
}
