$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this test from an ordinary PowerShell window, not as administrator.'
}
& "$PSScriptRoot\windows-capture-tests.exe" '-test.v' '-test.timeout=60s' 2>&1 |
    Tee-Object -FilePath "$PSScriptRoot\capture-selftest.txt"
if ($LASTEXITCODE -ne 0) { throw 'Capture self-test failed. See capture-selftest.txt.' }
Write-Host 'Process ownership and isolated packet tests passed. Real VPN, UAC, routes and DNS still require the GUI acceptance checks in README.md.'
