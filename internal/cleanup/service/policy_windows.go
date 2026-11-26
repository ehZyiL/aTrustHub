//go:build windows

package service

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func policyLocation(p PolicyBackupItem) (registry.Key, uint32, error) {
	var root registry.Key
	switch p.Hive {
	case "HKLM":
		root = registry.LOCAL_MACHINE
	case "HKCU":
		root = registry.CURRENT_USER
	default:
		return 0, 0, fmt.Errorf("不支持的策略根键: %s", p.Hive)
	}
	var view uint32
	switch p.View {
	case "32":
		view = registry.WOW64_32KEY
	case "64":
		view = registry.WOW64_64KEY
	case "":
	default:
		return 0, 0, fmt.Errorf("无效的策略视图: %s", p.View)
	}
	if p.Key == "" || p.Value == "" {
		return 0, 0, fmt.Errorf("缺少策略值定位参数")
	}
	return root, view, nil
}

func backupPolicyValue(f Finding) (PolicyBackupItem, error) {
	var p PolicyBackupItem
	p.Hive, _ = f.Params["hive"].(string)
	p.Key, _ = f.Params["key"].(string)
	p.View, _ = f.Params["view"].(string)
	p.Value, _ = f.Params["value"].(string)
	root, view, err := policyLocation(p)
	if err != nil {
		return p, err
	}
	k, err := registry.OpenKey(root, p.Key, registry.QUERY_VALUE|view)
	if err != nil {
		return p, err
	}
	defer k.Close()
	// The scanner only selects string policies. Fail closed on changed types.
	p.Data, p.Type, err = k.GetStringValue(p.Value)
	return p, err
}

func restorePolicyValue(p PolicyBackupItem) error {
	root, view, err := policyLocation(p)
	if err != nil {
		return err
	}
	if p.Type != 0 && p.Type != registry.SZ && p.Type != registry.EXPAND_SZ {
		return fmt.Errorf("不支持的策略值类型: %d", p.Type)
	}
	k, _, err := registry.CreateKey(root, p.Key, registry.SET_VALUE|view)
	if err != nil {
		return err
	}
	defer k.Close()
	if p.Type == registry.EXPAND_SZ {
		return k.SetExpandStringValue(p.Value, p.Data)
	}
	return k.SetStringValue(p.Value, p.Data)
}
