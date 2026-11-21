package wincapture

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Execute the production script with every DNS cmdlet replaced. These tests
// parse/run PowerShell without touching the machine's routes, DNS or registry.
func TestNRPTCompareScript(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell 7 is required for the script fixture")
	}
	id := strings.Repeat("a", 32)
	const owned = "$script:rules = @((Rule 'ConnectHub:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' @('corp.test','.corp.test') '198.18.0.2'))\n"
	for _, tc := range []struct {
		name, setup, mode string
		before, after     []string
		wantError         bool
		writes            int
	}{
		{"add", "", "update", nil, []string{"corp.test"}, false, 1},
		{"extend_union", owned, "update", []string{"corp.test"}, []string{"corp.test", "db.corp.test"}, false, 1},
		{"idempotent", owned, "update", nil, []string{"corp.test"}, false, 0},
		{"remove", owned, "update", []string{"corp.test"}, nil, false, 1},
		{"recover", owned, "recover", []string{"corp.test"}, []string{"b.test"}, false, 1},
		{"external_server", owned + "$script:rules[0].NameServers = @('192.0.2.53')\n", "recover", []string{"corp.test"}, nil, true, 0},
		{"external_namespace", owned + "$script:rules[0].Namespace = @('changed.test','.changed.test')\n", "update", []string{"corp.test"}, nil, true, 0},
		{"external_overlap", "$script:rules = @((Rule 'OtherVPN' @('.corp.test') '192.0.2.53'))\n", "update", nil, []string{"db.corp.test"}, true, 0},
		{"external_same_address", "$script:rules = @((Rule 'OtherVPN' @('.corp.test') '198.18.0.2'))\n", "update", nil, []string{"corp.test"}, true, 0},
		{"group_policy_override", owned + "$script:extraEffective = @((Rule '' @('.corp.test') '192.0.2.53'))\n", "verify", []string{"corp.test"}, []string{"corp.test"}, true, 0},
		{"ineffective", "$script:effectiveMissing = $true\n", "update", nil, []string{"corp.test"}, true, 1},
		{"legacy_record", owned, "empty", nil, nil, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script, err := nrptScript(id, dnsRecovery{Before: tc.before, After: tc.after, Address: "198.18.0.2"}, tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			wantError := "$false"
			if tc.wantError {
				wantError = "$true"
			}
			checks := "\nif ($failed -ne " + wantError + ") { throw ('Unexpected failure: '+$failure) }\n"
			checks += "if ($script:writes -ne " + strconv.Itoa(tc.writes) + ") { throw ('Wrong writes: '+$script:writes) }\n"
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command", "-")
			cmd.Stdin = strings.NewReader("$ErrorActionPreference = 'Stop'\n" + nrptMockCmdlets + tc.setup + "\n$failed = $false\n$failure = ''\ntry { & {\n" + script + "\n} } catch { $failed = $true; $failure = [string]$_ }\ntry {\n" + checks + "\nexit 0\n} catch { Write-Output $_; exit 1 }\n\n")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, output)
			}
		})
	}
}

const nrptMockCmdlets = `
$script:rules = @()
$script:extraEffective = @()
$script:effectiveMissing = $false
$script:writes = 0
function Rule($comment, $names, $servers) {
  return [pscustomobject]@{Name='fixture-rule'; Comment=$comment; Namespace=@($names); NameServers=@($servers)}
}
function Get-DnsClientNrptRule { return $script:rules }
function Get-DnsClientNrptPolicy([switch]$Effective) {
  if ($script:effectiveMissing) { return @() }
  return @($script:rules)+@($script:extraEffective)
}
function Add-DnsClientNrptRule($Namespace,$NameServers,$Comment,$DisplayName) {
  $script:writes++
  $script:rules += (Rule $Comment $Namespace $NameServers)
}
function Set-DnsClientNrptRule($Name,$Namespace,$NameServers,$Comment) {
  $script:writes++
  $script:rules = @((Rule $Comment $Namespace $NameServers))
}
function Remove-DnsClientNrptRule($Name,[switch]$Force) {
  $script:writes++
  $script:rules = @($script:rules | Where-Object { $_.Name -ne $Name })
}
function Clear-DnsClientCache {}
`
