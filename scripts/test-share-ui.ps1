[CmdletBinding()]
param(
    [ValidateRange(1, 100)]
    [int]$Count = 1,
    [string]$Run = '^TestShareUIProbe'
)

$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskArtifacts = Join-Path $taskRoot 'build/share-lifecycle-checks'
New-Item -ItemType Directory -Force -Path $taskArtifacts | Out-Null
$taskVirtual = Join-Path $taskRoot 'internal/desktop/share_ui_probe_test.go'
$taskSource = Join-Path $PSScriptRoot 'diagnostics/share_ui_test.go.txt'
$taskOverlay = Join-Path $taskArtifacts 'share-ui-overlay.json'
@{ Replace = @{ $taskVirtual = $taskSource } } | ConvertTo-Json -Depth 3 |
    Set-Content -Encoding utf8NoBOM -LiteralPath $taskOverlay

$taskSavedEnv = @{}
foreach ($taskKey in @('GOWORK', 'GOFLAGS', 'GOOS', 'GOARCH')) {
    $taskSavedEnv[$taskKey] = [Environment]::GetEnvironmentVariable($taskKey, 'Process')
}
try {
    $env:GOWORK = 'off'
    $env:GOFLAGS = ''
    $env:GOOS = ''
    $env:GOARCH = ''
    go -C $taskRoot test -mod=readonly -overlay $taskOverlay ./internal/desktop `
        -run $Run -count $Count -timeout 45s -v 2>&1 |
        Tee-Object -FilePath (Join-Path $taskArtifacts 'share-ui-probe.log')
    $taskExit = $LASTEXITCODE
} finally {
    foreach ($taskKey in $taskSavedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($taskKey, $taskSavedEnv[$taskKey], 'Process')
    }
}
exit $taskExit
