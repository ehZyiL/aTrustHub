param([string]$WorkerPath)

$ErrorActionPreference = 'Stop'
if (-not $WorkerPath) {
    # 新包把 worker 放在 core/；拆分前的包和本机开发目录仍是平铺的。
    $WorkerPath = Join-Path $PSScriptRoot 'core\easyconnect-worker.exe'
    if (-not (Test-Path -LiteralPath $WorkerPath -PathType Leaf)) {
        $WorkerPath = Join-Path $PSScriptRoot 'easyconnect-worker.exe'
    }
}
if (-not (Test-Path -LiteralPath $WorkerPath -PathType Leaf)) {
    throw "Worker binary not found: $WorkerPath (use the complete bundle, worker lives in core\\)."
}
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = (Resolve-Path -LiteralPath $WorkerPath).Path
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$info.RedirectStandardInput = $true
$info.RedirectStandardOutput = $true
$info.RedirectStandardError = $true
$info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
$worker = [Diagnostics.Process]::Start($info)
try {
    # Invalid configuration must fail locally, with a versioned IPC reply.
    # No credentials, DNS lookup or VPN connection is involved.
    $worker.StandardInput.WriteLine('{"version":6,"session":"bundle-check","type":"start","config":{}}')
    $worker.StandardInput.Close()
    $output = $worker.StandardOutput.ReadToEndAsync()
    $discarded = $worker.StandardError.ReadToEndAsync()
    if (-not $worker.WaitForExit(5000)) {
        $worker.Kill()
        throw 'Worker IPC self-test timed out.'
    }
    $reply = $output.GetAwaiter().GetResult() | ConvertFrom-Json
    if ($worker.ExitCode -ne 1 -or $null -eq $reply -or $reply.version -ne 6 -or $reply.session -ne 'bundle-check' -or $reply.type -ne 'error' -or -not $reply.error) {
        throw 'Worker protocol mismatch: rebuild the standalone worker with GOWORK=off and replace the complete bundle.'
    }
    Write-Host 'Worker protocol v6 verified; invalid configuration rejected before network access.'
} finally {
    $worker.Dispose()
}
