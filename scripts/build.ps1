$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskSavedEnv = @{}
foreach ($taskKey in @('GOWORK', 'GOFLAGS', 'GOOS', 'GOARCH', 'GOTOOLCHAIN')) {
    $taskSavedEnv[$taskKey] = [Environment]::GetEnvironmentVariable($taskKey, 'Process')
}
try {
    $env:GOWORK = 'off'
    $env:GOFLAGS = '-mod=readonly'
    $env:GOOS = ''
    $env:GOARCH = ''
    $env:GOTOOLCHAIN = 'local'
    $taskGo = if ($env:GO) { $env:GO } else { 'go' }
    & $taskGo -C $taskRoot run ./scripts/buildtool -root $taskRoot @args
    $taskExit = $LASTEXITCODE
} finally {
    foreach ($taskKey in $taskSavedEnv.Keys) {
        [Environment]::SetEnvironmentVariable($taskKey, $taskSavedEnv[$taskKey], 'Process')
    }
}
exit $taskExit
