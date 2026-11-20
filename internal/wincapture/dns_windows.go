package wincapture

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func powershell(ctx context.Context, script string) error {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "-")
	cmd.Stdin = strings.NewReader("$ErrorActionPreference = 'Stop'\ntry {\n" + script + "\nexit 0\n} catch { exit 1 }\n\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		return errors.New("Windows DNS 策略操作失败；请检查系统策略和管理员权限")
	}
	return nil
}

func installNRPT(ctx context.Context, id string, domains []string, address string) (func() error, error) {
	if err := journalSession(id); err != nil {
		return nil, errors.New("无法记录本次 DNS 恢复信息，尚未安装 DNS 策略")
	}
	// Values come from Config.validate and the locally allocated adapter IP.
	// The preflight reads effective policy (including domain policy/Tailscale)
	// and refuses overlaps; existing policy is never removed or overwritten.
	var names []string
	for _, domain := range domains {
		names = append(names, "'"+domain+"'", "'."+domain+"'")
	}
	cleanup := func() error {
		if err := removeNRPT(context.Background(), id); err != nil {
			return err
		}
		return clearJournal(id)
	}
	script := "$wanted = @(" + strings.Join(names, ",") + ")\n" + `
$existing = @(Get-DnsClientNrptPolicy -Effective) + @(Get-DnsClientNrptRule)
foreach ($rule in $existing) {
  foreach ($ns in $rule.Namespace) {
    foreach ($target in $wanted) {
      $left = ([string]$ns).Trim('.').ToLowerInvariant()
      $right = $target.Trim('.').ToLowerInvariant()
      if ($left -eq '' -or $left -eq $right -or $left.EndsWith('.'+$right) -or $right.EndsWith('.'+$left)) {
        throw 'Existing DNS policy overlaps requested namespace'
      }
    }
  }
}
` + "Add-DnsClientNrptRule -Namespace $wanted -NameServers '" + address + "' -Comment 'EasyConnectHub:" + id + "' -DisplayName 'EasyConnect Hub managed capture' | Out-Null\n" +
		"$effective = @(Get-DnsClientNrptPolicy -Effective)\nforeach ($target in $wanted) {\n" +
		"  $matched = @($effective | Where-Object { $_.Namespace -contains $target -and $_.NameServers -contains '" + address + "' })\n" +
		"  if ($matched.Count -eq 0) { throw 'Local DNS policy did not become effective' }\n}\n"
	if err := powershell(ctx, script); err != nil {
		return cleanup, err
	}
	return cleanup, nil
}

func removeNRPT(ctx context.Context, id string) error {
	if !validID(id) {
		return errors.New("DNS 清理标识无效")
	}
	return powershell(ctx, "$owned = @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'EasyConnectHub:"+id+"' })\n"+
		"foreach ($rule in $owned) { Remove-DnsClientNrptRule -Name $rule.Name -Force }\n"+
		"if ($owned.Count -gt 0) { Clear-DnsClientCache }\n")
}
