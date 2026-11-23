# collect-sangfor-state.ps1 -- read-only snapshot / diff tool for Sangfor (EasyConnect / aTrust) installs.
#
# Why: docs/design/maintenance.md section 12 lists "unknown until seen on a real machine".
# This script answers those questions by capturing the machine state before and after an
# install, then diffing the two snapshots. It never writes to the registry, never stops a
# service, never deletes anything. Registry/file/network reads only.
#
# Usage (PowerShell 7):
#   pwsh -File scripts/collect-sangfor-state.ps1 -Mode capture -Tag before
#   pwsh -File scripts/collect-sangfor-state.ps1 -Mode capture -Tag after
#   pwsh -File scripts/collect-sangfor-state.ps1 -Mode compare `
#        -Baseline build/sangfor-state/state-before.json `
#        -Current  build/sangfor-state/state-after.json
#
# Exit codes: 0 ok, 1 usage error, 2 capture failed.

[CmdletBinding()]
param(
    [ValidateSet('capture', 'compare', 'list')]
    [string]$Mode = 'capture',
    [string]$Tag = '',
    [string]$OutDir = '',
    [string]$Baseline = '',
    [string]$Current = ''
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Off

# Same keyword set as docs/design/maintenance.md section 5.3, both families merged.
$KW = 'sangfor|深信服|atrust|ingress|eas(y)?connect|eaio|nac_monitor|nac_agent|sdpvnic|windivert|sfremovecallback|sangforhelpertool|sjobber'

# ProgIDs seen in EasyConnect 7.6.7 Uninstall.exe (section 5.2 of the design doc).
$PROGIDS = @(
    'SangforBHO.SangforHelper', 'SangforBHO.SangforIEBHO', 'SangforCDC.Server',
    'SangforCore.SangforCoreCom', 'SangforL3Vpn.L3Vpn', 'SangforSddn.Sddn',
    'SangforWebUICtrl.1'
)

$FIXED_KEYS = @(
    'HKLM:\SOFTWARE\Sangfor',
    'HKLM:\SOFTWARE\WOW6432Node\Sangfor',
    'HKCU:\SOFTWARE\Sangfor',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Ingress Manager'
)

$UNINSTALL_ROOTS = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

$WINSOCK = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries',
    'HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\winsock2\Catalog_Entries',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\winsock2\Catalog_Entries64',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\winsock2\Catalog_Entries',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\winsock2\Catalog_Entries64'
)

# ---------------------------------------------------------------- helpers

# Paths of this repo / this app must never be reported as a Sangfor leftover: they contain
# the same words for unrelated reasons (aTrustHub, connect-hub, easyconnect-worker).
$EXCLUDE = 'atrusthub|connect-hub|easy-connect|easyconnect-worker|easyconnect-check|easyconnect-hub|easyconnect hub'

function Test-Noise {
    param([string]$Text)
    return ($Text -match $EXCLUDE)
}

function Add-Fact {
    param($Facts, [string]$Key, [string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { $Value = '' }
    $Facts[$Key] = $Value
}

function Safe {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body } catch { Add-Fact $script:Facts "error:$Name" ($_.Exception.Message -replace '\s+', ' ') }
}

function Decode-Utf16Strings {
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 4) { return @() }
    $n = $Bytes.Length - ($Bytes.Length % 2)
    $chars = New-Object char[] ($n / 2)
    for ($i = 0; $i -lt $n; $i += 2) {
        $chars[$i / 2] = [char]([int]$Bytes[$i] -bor ([int]$Bytes[$i + 1] -shl 8))
    }
    $s = -join $chars
    return @([regex]::Matches($s, '[\x20-\x7E]{4,}') | ForEach-Object { $_.Value })
}

function Get-PropText {
    param($Item, [string]$Name)
    try {
        $v = $Item.GetValue($Name, $null)
        if ($null -eq $v) { return '' }
        if ($v -is [array]) { return ($v -join '|') }
        return [string]$v
    } catch { return '' }
}

# ---------------------------------------------------------------- capture

function Invoke-Capture {
    $script:Facts = [ordered]@{}
    $Facts = $script:Facts

    Add-Fact $Facts 'meta:when' (Get-Date -Format 'o')
    Add-Fact $Facts 'meta:tag' $Tag
    Add-Fact $Facts 'meta:host' $env:COMPUTERNAME
    Add-Fact $Facts 'meta:os' ([System.Environment]::OSVersion.VersionString)
    Add-Fact $Facts 'meta:pwsh' $PSVersionTable.PSVersion.ToString()
    $elevated = $false
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $elevated = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }
    Add-Fact $Facts 'meta:elevated' ([string]$elevated)

    # --- services and drivers: SCM registry is the single source of truth
    Safe 'services' {
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        $total = 0
        foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $total++
            $name = $k.PSChildName
            $img = Get-PropText $k 'ImagePath'
            $dsp = Get-PropText $k 'DisplayName'
            if (($name + ' ' + $img + ' ' + $dsp) -notmatch $KW) { continue }
            $type = Get-PropText $k 'Type'
            $start = Get-PropText $k 'Start'
            Add-Fact $Facts "service:$name" ("Type=$type Start=$start Display=$dsp Image=$img")
        }
        Add-Fact $Facts 'count:services' ([string]$total)
    }

    # --- driver files on disk
    Safe 'driverfiles' {
        foreach ($dir in @("$env:SystemRoot\System32\drivers", "$env:SystemRoot\SysWOW64\drivers")) {
            if (-not (Test-Path $dir)) { continue }
            foreach ($f in (Get-ChildItem $dir -File -ErrorAction SilentlyContinue)) {
                if ($f.Name -notmatch $KW) { continue }
                Add-Fact $Facts "driverfile:$($f.FullName)" ("Size=$($f.Length) Ver=$($f.VersionInfo.FileVersion)")
            }
        }
    }

    # --- DriverStore packages
    Safe 'driverstore' {
        $repo = "$env:SystemRoot\System32\DriverStore\FileRepository"
        $total = 0
        if (Test-Path $repo -ErrorAction SilentlyContinue) {
            foreach ($d in (Get-ChildItem $repo -Directory -ErrorAction SilentlyContinue)) {
                $total++
                if ($d.Name -notmatch $KW) { continue }
                Add-Fact $Facts "driverstore:$($d.Name)" $d.FullName
            }
        }
        Add-Fact $Facts 'count:driverstore' ([string]$total)
    }

    # --- uninstall entries
    # Matching on DisplayName alone is NOT enough: the tenant build renames the entry to its
    # own brand (observed: "EasyConnect" -> "中原招标采购交易平台") after the first gateway
    # login. Publisher, the key name and the uninstall path are the stable anchors.
    Safe 'uninstall' {
        $total = 0
        foreach ($root in $UNINSTALL_ROOTS) {
            if (-not (Test-Path $root -ErrorAction SilentlyContinue)) { continue }
            foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
                $total++
                $dsp = Get-PropText $k 'DisplayName'
                $pub = Get-PropText $k 'Publisher'
                $un = Get-PropText $k 'UninstallString'
                $quiet = Get-PropText $k 'QuietUninstallString'
                $loc = Get-PropText $k 'InstallLocation'
                $ver = Get-PropText $k 'DisplayVersion'
                $hay = "$($k.PSChildName) $dsp $pub $un $loc"
                if ($hay -notmatch $KW -or (Test-Noise $hay)) { continue }
                Add-Fact $Facts "uninstall:$($k.PSChildName)" ("Display=$dsp Publisher=$pub Version=$ver Location=$loc Uninstall=$un Quiet=$quiet")
            }
        }
        Add-Fact $Facts 'count:uninstallentries' ([string]$total)
    }

    # --- shortcuts left in the public desktop / start menu
    Safe 'shortcuts' {
        foreach ($dir in @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu", "$env:APPDATA\Microsoft\Windows\Start Menu")) {
            if (-not $dir) { continue }
            $exists = $false
            try { $exists = Test-Path -LiteralPath $dir -ErrorAction Stop } catch { $exists = $false }
            if (-not $exists) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $dir -Recurse -Depth 2 -Filter *.lnk -ErrorAction SilentlyContinue)) {
                $target = ''
                try { $target = (New-Object -ComObject WScript.Shell).CreateShortcut($f.FullName).TargetPath } catch { }
                if (("$($f.FullName) $target") -notmatch $KW) { continue }
                if (Test-Noise "$($f.FullName) $target") { continue }
                Add-Fact $Facts "shortcut:$($f.FullName)" "Target=$target"
            }
        }
    }

    # --- fixed registry trees (recursive key list)
    Safe 'fixedkeys' {
        foreach ($root in $FIXED_KEYS) {
            if (-not (Test-Path $root)) { continue }
            Add-Fact $Facts "regkey:$root" 'present'
            foreach ($sub in (Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue)) {
                Add-Fact $Facts "regkey:$($sub.Name)" 'present'
            }
        }
    }

    # --- Services subtree keys whose name matches the keywords (orphans with no SCM image)
    Safe 'servicesubkeys' {
        $root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
        foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            if ($k.PSChildName -match $KW) { Add-Fact $Facts "svcsubkey:$($k.PSChildName)" 'present' }
        }
    }

    # --- Winsock catalogs: the entry that survives a bad uninstall and breaks name resolution
    Safe 'winsock' {
        $total = 0
        foreach ($root in $WINSOCK) {
            if (-not (Test-Path $root -ErrorAction SilentlyContinue)) { continue }
            foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
                $total++
                $blob = $null
                try { $blob = $k.GetValue('PackedCatalogItem', $null) } catch { }
                $paths = @()
                if ($blob -is [byte[]]) { $paths = Decode-Utf16Strings $blob }
                $lib = Get-PropText $k 'LibraryPath'
                $disp = Get-PropText $k 'DisplayString'
                $proto = Get-PropText $k 'ProtocolName'
                $text = (($paths + @($lib, $disp, $proto)) -join ' ')
                if ($text -notmatch $KW) { continue }
                $id = ($root -replace '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\', '')
                Add-Fact $Facts "winsock:$id/$($k.PSChildName)" ("Lib=$lib Disp=$disp Proto=$proto Paths=" + (($paths | Select-Object -Unique) -join ','))
            }
        }
        Add-Fact $Facts 'count:winsockentries' ([string]$total)
    }

    # --- BHO registrations and known ProgIDs
    Safe 'bho' {
        $total = 0
        $bho = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        if (Test-Path $bho -ErrorAction SilentlyContinue) {
            foreach ($k in (Get-ChildItem $bho -ErrorAction SilentlyContinue)) {
                $total++
                $clsid = $k.PSChildName
                $server = ''
                foreach ($hive in @('HKLM:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID')) {
                    $p = "$hive\$clsid\InprocServer32"
                    if (Test-Path $p -ErrorAction SilentlyContinue) { $server = [string](Get-ItemProperty $p -ErrorAction SilentlyContinue).'(default)' }
                }
                if (($clsid + ' ' + $server) -notmatch $KW) { continue }
                Add-Fact $Facts "bho:$clsid" "Server=$server"
            }
        }
        Add-Fact $Facts 'count:bho' ([string]$total)
        foreach ($progId in $PROGIDS) {
            foreach ($hive in @('HKLM:\SOFTWARE\Classes', 'HKLM:\SOFTWARE\WOW6432Node\Classes')) {
                $p = "$hive\$progId"
                if (Test-Path $p -ErrorAction SilentlyContinue) { Add-Fact $Facts "progid:$progId" $p }
            }
        }
    }

    # --- network adapters (a leftover virtual NIC shows up here, not in SCM)
    Safe 'adapters' {
        foreach ($a in (Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
            $text = "$($a.Name) $($a.InterfaceDescription) $($a.DriverDescription) $($a.InterfaceAlias)"
            if ($text -notmatch $KW) { continue }
            Add-Fact $Facts "adapter:$($a.Name)" ("Desc=$($a.InterfaceDescription) Driver=$($a.DriverDescription) Status=$($a.Status) Id=$($a.InterfaceGuid)")
        }
        Add-Fact $Facts 'count:adapters' ([string](@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue).Count))
    }

    # --- processes
    Safe 'processes' {
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            $path = ''
            try { $path = $p.Path } catch { }
            if (("$($p.ProcessName) $path") -notmatch $KW) { continue }
            if (Test-Noise "$($p.ProcessName) $path") { continue }
            Add-Fact $Facts "process:$($p.ProcessName)" "Pid=$($p.Id) Path=$path"
        }
    }

    # --- firewall rules that point at a Sangfor executable
    Safe 'firewall' {
        $filters = Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        foreach ($f in $filters) {
            if ([string]$f.Program -notmatch $KW) { continue }
            if (Test-Noise ([string]$f.Program)) { continue }
            Add-Fact $Facts "firewall:$($f.InstanceID)" ("Program=$($f.Program)")
        }
    }

    # --- scheduled tasks
    Safe 'tasks' {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ($t.TaskName -notmatch $KW) { continue }
            Add-Fact $Facts "task:$($t.TaskPath)$($t.TaskName)" ([string]$t.State)
        }
        foreach ($n in @('aTrustHubTUN')) {
            if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) { Add-Fact $Facts "task:$n" 'present' }
        }
    }

    # --- DOS Devices (workspace virtual drives)
    Safe 'dosdevices' {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\DOS Devices'
        if (Test-Path $p) {
            $k = Get-Item $p
            foreach ($n in $k.GetValueNames()) {
                $v = [string]$k.GetValue($n)
                if ($n -match '^[A-Za-z]:$' -or $v -match $KW) { Add-Fact $Facts "dosdev:$n" $v }
            }
        }
    }

    # --- root certificates (EasyConnect ships its own CA)
    Safe 'certs' {
        foreach ($c in (Get-ChildItem 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue)) {
            if ($c.Subject -match $KW) { Add-Fact $Facts "cert:$($c.Thumbprint)" $c.Subject }
        }
    }

    # --- files in the usual install locations (depth-limited)
    Safe 'files' {
        $roots = @(
            $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData,
            $env:LOCALAPPDATA, $env:APPDATA,
            "$env:SystemRoot\System32\config\systemprofile",
            "$env:SystemRoot\Prefetch"
        )
        foreach ($root in $roots) {
            if (-not $root) { continue }
            $exists = $false
            try { $exists = Test-Path -LiteralPath $root -ErrorAction Stop } catch { $exists = $false }
            if (-not $exists) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -Depth 3 -ErrorAction SilentlyContinue)) {
                if ($f.Name -notmatch $KW) { continue }
                if ($f.FullName -match '\\Revo') { continue }
                if (Test-Noise $f.FullName) { continue }
                Add-Fact $Facts "file:$($f.FullName)" ("$($f.Length)")
            }
        }
    }

    return [ordered]@{ meta = [ordered]@{}; facts = $Facts }
}

# ---------------------------------------------------------------- compare

function Show-Diff {
    param([string]$BaselinePath, [string]$CurrentPath)
    if (-not (Test-Path $BaselinePath)) { Write-Error "baseline not found: $BaselinePath"; exit 1 }
    if (-not (Test-Path $CurrentPath)) { Write-Error "current not found: $CurrentPath"; exit 1 }
    $b = (Get-Content $BaselinePath -Raw | ConvertFrom-Json -AsHashtable).facts
    $c = (Get-Content $CurrentPath -Raw | ConvertFrom-Json -AsHashtable).facts
    $bMeta = (Get-Content $BaselinePath -Raw | ConvertFrom-Json -AsHashtable).meta
    $cMeta = (Get-Content $CurrentPath -Raw | ConvertFrom-Json -AsHashtable).meta

    $added = @(); $removed = @(); $changed = @()
    foreach ($k in $c.Keys) {
        if ($k -like 'meta:*') { continue }
        if (-not $b.Contains($k)) { $added += $k }
        elseif ($b[$k] -ne $c[$k]) { $changed += $k }
    }
    foreach ($k in $b.Keys) {
        if ($k -like 'meta:*') { continue }
        if (-not $c.Contains($k)) { $removed += $k }
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# Sangfor state diff")
    $lines.Add("")
    $lines.Add("baseline: $BaselinePath  (tag=$($bMeta['tag']) at $($bMeta['when']))")
    $lines.Add("current : $CurrentPath  (tag=$($cMeta['tag']) at $($cMeta['when']))")
    $lines.Add("")
    $lines.Add("added=$($added.Count) removed=$($removed.Count) changed=$($changed.Count)")
    $lines.Add("")

    function Emit($title, $keys, $src, $other) {
        $lines.Add("=== $title ($($keys.Count)) ===")
        foreach ($k in ($keys | Sort-Object)) {
            $lines.Add(("{0,-72} {1}" -f $k, $src[$k]))
        }
        $lines.Add("")
    }
    Emit 'ADDED' $added $c $b
    Emit 'REMOVED' $removed $b $c
    Emit 'CHANGED' $changed $c $b

    $text = $lines -join [Environment]::NewLine
    Write-Output $text
    $outFile = [System.IO.Path]::ChangeExtension($CurrentPath, '.diff.txt')
    Set-Content -Path $outFile -Value $text -Encoding utf8
    Write-Output "written: $outFile"
}

# ---------------------------------------------------------------- list

function Show-List {
    param([string]$Path)
    if (-not (Test-Path $Path)) { Write-Error "not found: $Path"; exit 1 }
    $j = Get-Content $Path -Raw | ConvertFrom-Json -AsHashtable
    foreach ($k in ($j.facts.Keys | Sort-Object)) {
        if ($k -like 'meta:*') { continue }
        "{0,-72} {1}" -f $k, $j.facts[$k]
    }
}

# ---------------------------------------------------------------- main

if (-not $OutDir) {
    $OutDir = Join-Path $PSScriptRoot '..\build\sangfor-state'
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)

switch ($Mode) {
    'capture' {
        if (-not $Tag) { $Tag = Get-Date -Format 'yyyyMMdd-HHmmss' }
        New-Item -ItemType Directory -Force $OutDir | Out-Null
        $state = Invoke-Capture
        $file = Join-Path $OutDir "state-$Tag.json"
        $json = [ordered]@{ meta = $state.meta; facts = $state.facts }
        $json.meta['tag'] = $Tag
        $json.meta['when'] = $state.facts['meta:when']
        $json.meta['host'] = $state.facts['meta:host']
        $json.meta['elevated'] = $state.facts['meta:elevated']
        $json | ConvertTo-Json -Depth 6 | Set-Content -Path $file -Encoding utf8
        Write-Output "captured $($state.facts.Count) facts -> $file"
        if (-not $elevated) {
            Write-Output 'NOTE: capture was NOT elevated -- process Path, some certificates and some'
            Write-Output '      firewall rules will be missing. Compare only against captures made with'
            Write-Output '      the same privilege level.'
        }
        Write-Output ''
        Write-Output '--- facts mentioning the keywords ---'
        foreach ($k in ($state.facts.Keys | Sort-Object)) {
            if ($k -like 'meta:*' -or $k -like 'count:*') { continue }
            "{0,-70} {1}" -f $k, $state.facts[$k]
        }
        foreach ($k in ($state.facts.Keys | Where-Object { $_ -like 'count:*' } | Sort-Object)) {
            "{0,-70} {1}" -f $k, $state.facts[$k]
        }
    }
    'compare' {
        if (-not $Baseline) { $Baseline = Join-Path $OutDir 'state-before.json' }
        if (-not $Current) { $Current = Join-Path $OutDir 'state-after.json' }
        Show-Diff -BaselinePath $Baseline -CurrentPath $Current
    }
    'list' {
        if (-not $Current) { $Current = Join-Path $OutDir 'state-after.json' }
        Show-List -Path $Current
    }
}
