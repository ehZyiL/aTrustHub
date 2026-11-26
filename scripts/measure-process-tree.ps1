param(
    [Parameter(Mandatory)][int]$RootProcessId,
    [Parameter(Mandatory)][string]$OutputFile,
    [string]$Scenario = 'idle',
    [ValidateRange(1, 3600)][int]$Seconds = 20,
    [ValidateRange(100, 10000)][int]$IntervalMilliseconds = 500
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'This collector requires Windows process counters.' }
if (-not ('ConnectHubMeasure.WindowState' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace ConnectHubMeasure {
    public static class WindowState {
        [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr window);
    }
}
'@
}
$taskRoot = Get-Process -Id $RootProcessId
$taskRootStart = $taskRoot.StartTime.ToUniversalTime().Ticks
$taskSamples = [Collections.Generic.List[object]]::new()
$taskKnown = @{}
$taskKnown[$RootProcessId] = $taskRootStart
$taskWatch = [Diagnostics.Stopwatch]::StartNew()
while ($taskWatch.Elapsed.TotalSeconds -lt $Seconds) {
    $taskCurrentRoot = Get-Process -Id $RootProcessId -ErrorAction SilentlyContinue
    if (!$taskCurrentRoot -or $taskCurrentRoot.StartTime.ToUniversalTime().Ticks -ne $taskRootStart) {
        throw 'The measured root exited or its PID was reused; refusing an incomplete sample.'
    }
    # Follow the entire descendant tree. Keep identities of reparented children;
    # a PID reused by an unrelated process never becomes part of this sample.
    $taskAll = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,CreationDate,Name)
    $taskLive = @{}
    foreach ($taskEntry in $taskAll) {
        $taskId = [int]$taskEntry.ProcessId
        $taskStart = $taskEntry.CreationDate.ToUniversalTime().Ticks
        if ($taskKnown.ContainsKey($taskId) -and $taskKnown[$taskId] -eq $taskStart) { $taskLive[$taskId] = $taskStart }
    }
    # Get-Process and CIM creation timestamps may differ in precision. Root is
    # independently validated above; use its CIM identity for descendant walks.
    $taskRootEntry = $taskAll | Where-Object ProcessId -eq $RootProcessId
    if (!$taskRootEntry) { throw 'Root disappeared during process enumeration.' }
    $taskLive[$RootProcessId] = $taskRootEntry.CreationDate.ToUniversalTime().Ticks
    do {
        $taskAdded = $false
        foreach ($taskEntry in $taskAll) {
            $taskId = [int]$taskEntry.ProcessId
            $taskParent = [int]$taskEntry.ParentProcessId
            $taskStart = $taskEntry.CreationDate.ToUniversalTime().Ticks
            if (!$taskLive.ContainsKey($taskId) -and $taskLive.ContainsKey($taskParent) -and $taskStart -ge $taskLive[$taskParent]) {
                $taskLive[$taskId] = $taskStart
                $taskAdded = $true
            }
        }
    } while ($taskAdded)
    $taskRows = [Collections.Generic.List[object]]::new()
    foreach ($taskId in $taskLive.Keys) {
        $taskKnown[$taskId] = $taskLive[$taskId]
        $taskProcess = Get-Process -Id $taskId -ErrorAction SilentlyContinue
        if (!$taskProcess) { continue }
        # Recheck creation time before reading counters (CIM is microsecond precision).
        if ([Math]::Abs($taskProcess.StartTime.ToUniversalTime().Ticks - $taskLive[$taskId]) -gt 10000) { continue }
        $taskWindow = $taskProcess.MainWindowHandle
        $taskWindowState = if ($taskWindow -eq [IntPtr]::Zero) { 'no-main-window' }
            elseif ([ConnectHubMeasure.WindowState]::IsIconic($taskWindow)) { 'minimized' }
            elseif ([ConnectHubMeasure.WindowState]::IsWindowVisible($taskWindow)) { 'visible' }
            else { 'hidden' }
        $taskRows.Add([pscustomobject]@{
            pid = $taskId; name = $taskProcess.ProcessName
            private_bytes = $taskProcess.PrivateMemorySize64
            working_set = $taskProcess.WorkingSet64
            handles = $taskProcess.HandleCount
            cpu_seconds = $taskProcess.TotalProcessorTime.TotalSeconds
            window = $taskWindowState
        })
    }
    if (!($taskRows | Where-Object pid -eq $RootProcessId)) { throw 'Root counters missing.' }
    $taskSamples.Add([pscustomobject]@{
        elapsed_seconds = $taskWatch.Elapsed.TotalSeconds
        processes = @($taskRows.ToArray())
        private_bytes = ($taskRows | Measure-Object private_bytes -Sum).Sum
        working_set = ($taskRows | Measure-Object working_set -Sum).Sum
        handles = ($taskRows | Measure-Object handles -Sum).Sum
    })
    Start-Sleep -Milliseconds $IntervalMilliseconds
}
$taskOutputPath = [IO.Path]::GetFullPath($OutputFile)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($taskOutputPath)) | Out-Null
[pscustomobject]@{
    schema = 1; scenario = $Scenario; timestamp_utc = [DateTime]::UtcNow.ToString('o')
    root_pid = $RootProcessId; interval_ms = $IntervalMilliseconds
    note = 'Sampled descendants only; short-lived processes between samples may be missed. Working sets can share physical pages. External system services are excluded.'
    samples = @($taskSamples.ToArray())
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $taskOutputPath -Encoding utf8
Write-Output "Collected $($taskSamples.Count) process-tree samples: $taskOutputPath"
