package wincapture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
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
	// DnsClient ships with Windows PowerShell; the installed product must not
	// require the developer's optional PowerShell 7 installation.
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", "-")
	cmd.Stdin = strings.NewReader("$ErrorActionPreference = 'Stop'\ntry {\n" + script + "\nexit 0\n} catch { exit 1 }\n\n")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if cmd.Run() != nil {
		return errors.New("Windows DNS 策略校验或更新失败；已有外部修改将被保留")
	}
	return nil
}

type dnsRecovery struct {
	Before  []string `json:"Before"`
	After   []string `json:"After"`
	Address string   `json:"Address"`
}

func (r dnsRecovery) validate() error {
	address, err := netip.ParseAddr(r.Address)
	if err != nil || !netip.MustParsePrefix("198.18.0.0/16").Contains(address) {
		return errors.New("DNS 恢复地址无效")
	}
	for _, domains := range [][]string{r.Before, r.After} {
		if len(domains) > 256 {
			return errors.New("DNS 恢复后缀过多")
		}
		for _, domain := range domains {
			if len(domain) > 253 || !strings.Contains(domain, ".") || strings.Trim(domain, ".") != domain {
				return errors.New("DNS 恢复后缀无效")
			}
			for _, label := range strings.Split(domain, ".") {
				if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
					return errors.New("DNS 恢复后缀无效")
				}
				for _, c := range label {
					if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
						return errors.New("DNS 恢复后缀无效")
					}
				}
			}
		}
	}
	return nil
}

func updateNRPT(ctx context.Context, id string, before, after []string, address string) error {
	state := dnsRecovery{Before: before, After: after, Address: address}
	script, err := nrptScript(id, state, "update")
	if err != nil {
		return err
	}
	if err := journalDNS(id, state); err != nil {
		return errors.New("无法保存 DNS 差量恢复记录，尚未修改策略")
	}
	if err := powershell(ctx, script); err != nil {
		return err
	}
	if len(after) == 0 {
		return clearJournal(id)
	}
	return nil
}

func removeNRPT(ctx context.Context, id string) error {
	state, err := readJournalDNS(id)
	if err != nil {
		return err
	}
	mode := "recover"
	if state == nil {
		// Incomplete/legacy records cannot prove the current rule's values.
		mode = "empty"
		state = &dnsRecovery{Address: "198.18.0.2"}
	}
	script, err := nrptScript(id, *state, mode)
	if err != nil {
		return err
	}
	return powershell(ctx, script)
}

func checkNRPTActive(ctx context.Context, id string, domains []string, address string) error {
	script, err := nrptScript(id, dnsRecovery{Before: domains, After: domains, Address: address}, "verify")
	if err != nil {
		return err
	}
	return powershell(ctx, script)
}

// JSON is data, never interpolated as PowerShell syntax. The same comparison
// governs normal deltas, idempotent retries and crash recovery.
func nrptScript(id string, state dnsRecovery, mode string) (string, error) {
	if !validID(id) {
		return "", errors.New("DNS 清理标识无效")
	}
	if err := state.validate(); err != nil {
		return "", err
	}
	if mode != "update" && mode != "recover" && mode != "verify" && mode != "empty" {
		return "", errors.New("DNS 操作无效")
	}
	data, err := json.Marshal(struct {
		dnsRecovery
		ID   string
		Mode string
	}{state, id, mode})
	if err != nil {
		return "", err
	}
	return "$state = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(data) + "')) | ConvertFrom-Json\n" + nrptCompareScript, nil
}

const nrptCompareScript = `
function Names($values) {
  return @($values | ForEach-Object { ([string]$_).ToLowerInvariant() } | Sort-Object -Unique)
}
function Servers($rule) {
  return @($rule.NameServers | ForEach-Object { ([string]$_) -split '[,;\s]+' } | Where-Object { $_ -ne '' } | Sort-Object -Unique)
}
function SameNames($left, $right) {
  return ((Names $left) -join '|') -ceq ((Names $right) -join '|')
}
function SameRule($rule, $wanted) {
  return (SameNames $rule.Namespace $wanted) -and (SameNames (Servers $rule) @($state.Address))
}
function ExpandDomains($domains) {
  if ($null -eq $domains) { return @() }
  return @($domains | ForEach-Object { [string]$_; '.'+[string]$_ })
}
$before = @(ExpandDomains $state.Before)
$after = @(ExpandDomains $state.After)
$comment = 'EasyConnectHub:'+$state.ID
$localRules = @(Get-DnsClientNrptRule)
$owned = @($localRules | Where-Object { $_.Comment -ceq $comment })
if ($owned.Count -gt 1) { throw 'Duplicate ownership tag' }
if ($state.Mode -eq 'empty') {
  if ($owned.Count -ne 0) { throw 'Recovery record cannot verify existing policy' }
  return
}
if ($state.Mode -eq 'recover') {
  if ($owned.Count -eq 0) { return }
  if (!(SameRule $owned[0] $before) -and !(SameRule $owned[0] $after)) { throw 'Externally changed policy retained' }
  Remove-DnsClientNrptRule -Name $owned[0].Name -Force
  Clear-DnsClientCache
  return
}
$alreadyAfter = ($owned.Count -eq 0 -and $after.Count -eq 0) -or ($owned.Count -eq 1 -and (SameRule $owned[0] $after))
$wasBefore = ($owned.Count -eq 0 -and $before.Count -eq 0) -or ($owned.Count -eq 1 -and (SameRule $owned[0] $before))
if (!$alreadyAfter -and !$wasBefore) { throw 'Externally changed policy retained' }
if ($state.Mode -eq 'verify' -and !$alreadyAfter) { throw 'Managed policy is missing' }
$effective = @(Get-DnsClientNrptPolicy -Effective)
$externalLocal = @($localRules | Where-Object { $_.Comment -cne $comment })
foreach ($rule in @($externalLocal)+@($effective)) {
  foreach ($ns in @($rule.Namespace)) {
    $ownedEffective = $owned.Count -eq 1 -and @($owned[0].Namespace) -contains $ns -and (SameNames (Servers $rule) @($state.Address))
    if ($ownedEffective -and !($externalLocal -contains $rule)) { continue }
    foreach ($target in $after) {
      $left = ([string]$ns).Trim('.').ToLowerInvariant()
      $right = $target.Trim('.').ToLowerInvariant()
      if ($left -eq '' -or $left -eq $right -or $left.EndsWith('.'+$right) -or $right.EndsWith('.'+$left)) {
        throw 'External DNS policy overlaps requested namespace'
      }
    }
  }
}
if (!$alreadyAfter) {
  if ($after.Count -eq 0) {
    Remove-DnsClientNrptRule -Name $owned[0].Name -Force
  } elseif ($owned.Count -eq 0) {
    Add-DnsClientNrptRule -Namespace $after -NameServers $state.Address -Comment $comment -DisplayName 'EasyConnect Hub managed capture' | Out-Null
  } else {
    Set-DnsClientNrptRule -Name $owned[0].Name -Namespace $after -NameServers $state.Address -Comment $comment | Out-Null
  }
}
if ($after.Count -gt 0) {
  $effective = @(Get-DnsClientNrptPolicy -Effective)
  foreach ($target in $after) {
    $matched = @($effective | Where-Object { $_.Namespace -contains $target -and (SameNames (Servers $_) @($state.Address)) })
    if ($matched.Count -eq 0) { throw 'Managed DNS policy did not become effective' }
  }
}
if (!$alreadyAfter) { Clear-DnsClientCache }
`
