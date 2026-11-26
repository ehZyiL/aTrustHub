package firewall

// This script is the only privileged work the helper performs. It is kept in a
// portable file so its contract (BOM-less UTF-8 output, structured parameters)
// can be checked by tests on any platform.

// psFirewallScript is the only script the helper runs. The operation arrives as
// a JSON file and every value is passed to a cmdlet as a parameter, so no user
// text is ever interpolated into a command line. The result is written as
// BOM-less UTF-8: Windows PowerShell 5.1 prepends a BOM with -Encoding UTF8,
// which used to make a successful operation look unparseable.
const psFirewallScript = `
$ErrorActionPreference = 'Stop'
# Read the operation as UTF-8 explicitly. The default text input decodes with the
# system ANSI code page on Windows PowerShell 5.1, which turns a Chinese program
# path into mojibake and makes the rule target the wrong file.
$opText = [System.IO.File]::ReadAllText($env:CONNECT_HUB_FW_OP, (New-Object System.Text.UTF8Encoding($false)))
$op = $opText | ConvertFrom-Json
function Get-RuleState($name) {
  $r = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
  if ($null -eq $r) { return $null }
  $app  = $r | Get-NetFirewallApplicationFilter
  $port = $r | Get-NetFirewallPortFilter
  $addr = $r | Get-NetFirewallAddressFilter
  return [pscustomobject]@{
    name      = [string]$r.DisplayName
    direction = [string]$r.Direction
    action    = [string]$r.Action
    enabled   = [bool]$r.Enabled
    profile   = [string]$r.Profile
    program   = [string]$app.Program
    protocol  = [string]$port.Protocol
    localPort = [string]$port.LocalPort
    remote    = [string]($addr.RemoteAddress -join ',')
  }
}
$result = [ordered]@{ outcome = 'failed'; detail = ''; state = $null }
try {
  switch ($op.op) {
    'apply' {
      $rule = $op.rule
      $existing = Get-NetFirewallRule -DisplayName $rule.id -ErrorAction SilentlyContinue
      if ($null -ne $existing) { Remove-NetFirewallRule -DisplayName $rule.id }
      $profileArg = @($rule.profile -split ',' | ForEach-Object { $_.Trim() })
      $params = @{
        DisplayName = $rule.id
        Direction   = 'Inbound'
        Action      = 'Allow'
        Program     = $rule.programPath
        Protocol    = 'TCP'
        LocalPort   = [int]$rule.port
        Profile     = $profileArg
        Enabled     = 'True'
      }
      if ($rule.remoteIp) { $params['RemoteAddress'] = $rule.remoteIp }
      New-NetFirewallRule @params | Out-Null
      $state = Get-RuleState $rule.id
      if ($null -eq $state) { $result.outcome = 'failed'; $result.detail = '规则创建后读不到' }
      else { $result.outcome = 'created'; $result.state = $state }
    }
    'query' {
      $state = Get-RuleState $op.ruleId
      if ($null -eq $state) { $result.outcome = 'absent' }
      else { $result.outcome = 'present'; $result.state = $state }
    }
    'delete' {
      $existing = Get-NetFirewallRule -DisplayName $op.ruleId -ErrorAction SilentlyContinue
      if ($null -eq $existing) { $result.outcome = 'absent' }
      else {
        Remove-NetFirewallRule -DisplayName $op.ruleId
        $state = Get-RuleState $op.ruleId
        if ($null -eq $state) { $result.outcome = 'removed' }
        else { $result.outcome = 'failed'; $result.detail = '规则删除后仍然存在' }
      }
    }
    default { $result.outcome = 'failed'; $result.detail = '不支持的操作' }
  }
} catch {
  $result.outcome = 'failed'
  $result.detail = $_.Exception.Message
}
# Write BOM-less UTF-8. The default text encoder on Windows PowerShell 5.1
# prepends a byte-order mark, which makes the JSON unreadable for a strict decoder.
$json = $result | ConvertTo-Json -Compress -Depth 5
[System.IO.File]::WriteAllText($env:CONNECT_HUB_FW_OUT, $json, (New-Object System.Text.UTF8Encoding($false)))
`
