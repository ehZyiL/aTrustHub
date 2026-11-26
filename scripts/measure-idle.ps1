param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateRange(1, 300)][int]$WarmupSeconds = 5,
    [ValidateRange(1, 300)][int]$Seconds = 20
)
$ErrorActionPreference = 'Stop'
$taskExe = (Resolve-Path -LiteralPath $Executable).Path
$taskOut = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $taskOut) { throw 'Use a new output directory for each run; existing profiles are never reused.' }
if (Get-Process -Name connect-hub -ErrorAction SilentlyContinue) { throw 'Close the existing Hub before measuring; the single-instance lock would invalidate this run.' }
[IO.Directory]::CreateDirectory($taskOut) | Out-Null
$taskProfile = Join-Path $taskOut 'profile'
[IO.Directory]::CreateDirectory($taskProfile) | Out-Null
# Defaults can automatically restore the system proxy. Use an explicit fixture
# so this harness never changes global networking or contacts an update service.
@{
    version = 1; points = @(); localApps = @()
    settings = @{
        listenHost = '127.0.0.1'; aggregatePort = 1080; aggregateEnabled = $true
        captureMode = 'off'; tunEnabled = $false; autoRestoreAppCapture = $false
        autoCheckUpdate = $false; autoLoginOptIn = $true; simpleMode = $true
        secretStore = 'file'; lanShare = @{ enabled = $false }
    }
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $taskProfile 'config.json') -Encoding utf8NoBOM
if (-not ('ConnectHubMeasure.IsolatedWindow' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace ConnectHubMeasure {
    public static class IsolatedWindow {
        [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr window, int command);
    }
}
'@
}
$taskSaved = @{}
foreach ($taskKey in @('CONNECT_HUB_HOME', 'EASYCONNECT_HOME', 'EASYCONNECT_LOG')) {
    $taskSaved[$taskKey] = [Environment]::GetEnvironmentVariable($taskKey, 'Process')
}
$taskProcess = $null
try {
    $env:CONNECT_HUB_HOME = $taskProfile
    $env:EASYCONNECT_HOME = $taskProfile
    $env:EASYCONNECT_LOG = Join-Path $taskProfile 'app.log'
    $taskProcess = Start-Process -FilePath $taskExe -WorkingDirectory (Split-Path -Parent $taskExe) -WindowStyle Hidden -PassThru
    $taskStart = $taskProcess.StartTime.ToUniversalTime().Ticks
    Start-Sleep -Seconds $WarmupSeconds
    $taskProcess.Refresh()
    if ($taskProcess.HasExited) { throw "Isolated Hub exited during warmup (exit $($taskProcess.ExitCode))." }
    if ($taskProcess.MainWindowHandle -eq [IntPtr]::Zero) { throw 'Hub did not create its main window.' }
    # The application explicitly shows its window after startup. Hide only this
    # harness-owned window before sampling, using a fixed state in every run.
    [ConnectHubMeasure.IsolatedWindow]::ShowWindowAsync($taskProcess.MainWindowHandle, 0) | Out-Null
    & (Join-Path $PSScriptRoot 'measure-process-tree.ps1') -RootProcessId $taskProcess.Id -OutputFile (Join-Path $taskOut 'samples.json') -Scenario 'isolated-hidden-never-enabled' -Seconds $Seconds
    [pscustomobject]@{
        executable_sha256 = (Get-FileHash -LiteralPath $taskExe -Algorithm SHA256).Hash.ToLowerInvariant()
        warmup_seconds = $WarmupSeconds; measurement_seconds = $Seconds
        profile = 'explicit isolated fixture: no gateway, capture off, updates off, sharing off'
        window = 'hidden after warmup; measurements >=30 seconds include the existing working-set trim behavior'
        stop = 'terminate only the process created by this harness after sampling'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskOut 'run.json') -Encoding utf8
} finally {
    # This harness uses only an empty profile and never enables proxy/capture,
    # cleanup or a VPN. Do not reuse this termination policy for active sessions.
    if ($taskProcess) {
        $taskCurrent = Get-Process -Id $taskProcess.Id -ErrorAction SilentlyContinue
        if ($taskCurrent -and $taskCurrent.StartTime.ToUniversalTime().Ticks -eq $taskStart -and $taskCurrent.Path -eq $taskExe) {
            Stop-Process -Id $taskCurrent.Id
            $taskProcess.WaitForExit()
        }
    }
    foreach ($taskKey in $taskSaved.Keys) {
        [Environment]::SetEnvironmentVariable($taskKey, $taskSaved[$taskKey], 'Process')
    }
}
