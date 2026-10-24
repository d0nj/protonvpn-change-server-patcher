#requires -Version 5.1
<#
.SYNOPSIS
    Patches the Proton VPN Windows client so the free-tier "Change Server"
    cooldown is never enforced, by rewriting ChangeServerModerator.CanChangeServer
    to always return true.

.DESCRIPTION
    The method is located by NAME through the assembly's CLI metadata (never by
    byte offset), so the patch keeps working across client updates as long as
    Proton keeps the class/method names. The original file is backed up before
    the first patch of each version and can be restored at any time.

    Actions:
      Patch    Apply the patch to the newest v* install (or -DllPath).
      Status   Report what would be patched and whether it is already patched.
      Restore  Restore the backup for the current client version.

.NOTES
    Patch and Restore write into Program Files and require elevation.
    Status is read-only.
#>
[CmdletBinding()]
param(
    [ValidateSet('Patch', 'Restore', 'Status')]
    [string]$Action = 'Status',

    [string]$DllPath,

    [string]$BackupRoot = (Join-Path $env:LOCALAPPDATA 'ProtonChangeServerPatcher\Backups'),

    [string]$LogFile = (Join-Path $env:LOCALAPPDATA 'ProtonChangeServerPatcher\patcher.log')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$TargetTypeName = 'ChangeServerModerator'
$TargetMethodName = 'CanChangeServer'
$ClientRoot = Join-Path ${env:ProgramFiles} 'Proton\VPN'
$ClientDllName = 'ProtonVPN.Client.Logic.Connection.dll'

function Write-Log {
    param([string]$Message)
    $line = '{0:u} {1}' -f (Get-Date), $Message
    Write-Host $line
    try {
        $dir = Split-Path $LogFile -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    } catch { }
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ClientDllPath {
    if ($DllPath) { return (Resolve-Path $DllPath).Path }

    if (-not (Test-Path $ClientRoot)) { throw "Proton VPN install root not found: $ClientRoot" }
    $versionDirs = Get-ChildItem -Path $ClientRoot -Directory |
        Where-Object { $_.Name -match '^v\d' } |
        Sort-Object { [version]($_.Name.TrimStart('v')) } -ErrorAction SilentlyContinue
    if (-not $versionDirs) { throw "No v* version folders under $ClientRoot" }
    $newest = $versionDirs[-1].FullName
    return (Join-Path $newest $ClientDllName)
}

# ---------- minimal ECMA-335 metadata reader ----------

function Get-PatchTargets {
    param(
        [byte[]]$Bytes,
        [string]$TypeName,
        [string]$MethodName
    )

    $peOff = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ([BitConverter]::ToUInt32($Bytes, $peOff) -ne 0x00004550) { throw 'Not a PE image' }
    $numSections = [BitConverter]::ToUInt16($Bytes, $peOff + 6)
    $optSize = [BitConverter]::ToUInt16($Bytes, $peOff + 20)
    $opt = $peOff + 24
    if ([BitConverter]::ToUInt16($Bytes, $opt) -ne 0x020B) { throw 'Expected PE32+ (x64) image' }

    $sections = New-Object System.Collections.ArrayList
    $sectStart = $opt + $optSize
    for ($i = 0; $i -lt $numSections; $i++) {
        $o = $sectStart + 40 * $i
        [void]$sections.Add(@{
            Va = [BitConverter]::ToUInt32($Bytes, $o + 12)
            Vs = [Math]::Max([BitConverter]::ToUInt32($Bytes, $o + 8), [BitConverter]::ToUInt32($Bytes, $o + 16))
            Ro = [BitConverter]::ToUInt32($Bytes, $o + 20)
        })
    }

    function Convert-RvaToOffset([uint32]$Rva) {
        foreach ($s in $sections) {
            if ($Rva -ge $s.Va -and $Rva -lt ($s.Va + $s.Vs)) { return [int]($s.Ro + ($Rva - $s.Va)) }
        }
        throw ("RVA 0x{0:X} is not mapped by any section" -f $Rva)
    }

    $clrRva = [BitConverter]::ToUInt32($Bytes, $opt + 112 + 14 * 8)
    if ($clrRva -eq 0) { throw 'No CLI header: this is not a managed assembly' }
    $cli = Convert-RvaToOffset $clrRva
    $metaRva = [BitConverter]::ToUInt32($Bytes, $cli + 8)
    $meta = Convert-RvaToOffset $metaRva
    if ([BitConverter]::ToUInt32($Bytes, $meta) -ne 0x424A5342) { throw 'Bad metadata root (BSJB expected)' }

    $versionLength = [BitConverter]::ToInt32($Bytes, $meta + 12)
    $p = $meta + 16 + $versionLength + 2
    $streamCount = [BitConverter]::ToUInt16($Bytes, $p); $p += 2

    $streams = @{}
    for ($i = 0; $i -lt $streamCount; $i++) {
        $sOffset = [BitConverter]::ToInt32($Bytes, $p)
        $sSize = [BitConverter]::ToInt32($Bytes, $p + 4)
        $p += 8
        $nameEnd = $p
        while ($Bytes[$nameEnd] -ne 0) { $nameEnd++ }
        $name = [Text.Encoding]::ASCII.GetString($Bytes, $p, $nameEnd - $p)
        $p = $nameEnd + 1
        $p = [int]([Math]::Ceiling($p / 4.0) * 4)
        $streams[$name] = $meta + $sOffset
    }
    if (-not $streams.ContainsKey('#~')) { throw 'Compressed metadata stream #~ not found (ENC assemblies are unsupported)' }
    if (-not $streams.ContainsKey('#Strings')) { throw '#Strings heap not found' }
    if (-not $streams.ContainsKey('#Blob')) { throw '#Blob heap not found' }
    $stringsHeap = $streams['#Strings']
    $blobHeap = $streams['#Blob']

    $til = $streams['#~']
    $heapFlags = $Bytes[$til + 6]
    $strSize = 2; if ($heapFlags -band 1) { $strSize = 4 }
    $guidSize = 2; if ($heapFlags -band 2) { $guidSize = 4 }
    $blobSize = 2; if ($heapFlags -band 4) { $blobSize = 4 }

    $validMask = [BitConverter]::ToUInt64($Bytes, $til + 8)
    $rowPtr = $til + 24
    $rowCounts = @{}
    $presentTables = @()
    for ($t = 0; $t -lt 64; $t++) {
        if ((($validMask -shr $t) -band 1) -eq 1) {
            $rowCounts[$t] = [BitConverter]::ToUInt32($Bytes, $rowPtr)
            $rowPtr += 4
            $presentTables += $t
        }
    }

    function Get-SimpleIndexSize([int]$Table) {
        if ($rowCounts.ContainsKey($Table) -and $rowCounts[$Table] -ge 0x10000) { return 4 }
        return 2
    }
    function Get-CodedIndexSize([int[]]$Tables, [int]$TagBits) {
        $limit = [uint64]1 -shl (16 - $TagBits)
        foreach ($t in $Tables) {
            if ($rowCounts.ContainsKey($t) -and [uint64]$rowCounts[$t] -ge $limit) { return 4 }
        }
        return 2
    }

    $TypeDefOrRef = @(0x02, 0x01, 0x1B)
    $HasCustomAttribute = @(0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B)

    function Get-RowSize([int]$Table) {
        switch ($Table) {
            0x00 { 2 + $strSize + 3 * $guidSize }
            0x01 { (Get-CodedIndexSize @(0x00, 0x1A, 0x23, 0x01) 2) + 2 * $strSize }
            0x02 { 4 + 2 * $strSize + (Get-CodedIndexSize $TypeDefOrRef 2) + (Get-SimpleIndexSize 0x04) + (Get-SimpleIndexSize 0x06) }
            0x03 { Get-SimpleIndexSize 0x04 }
            0x04 { 2 + $strSize + $blobSize }
            0x05 { Get-SimpleIndexSize 0x06 }
            0x06 { 8 + $strSize + $blobSize + (Get-SimpleIndexSize 0x08) }
            0x07 { Get-SimpleIndexSize 0x08 }
            0x08 { 4 + $strSize }
            0x09 { (Get-SimpleIndexSize 0x02) + (Get-CodedIndexSize $TypeDefOrRef 2) }
            0x0A { (Get-CodedIndexSize @(0x02, 0x01, 0x1A, 0x06, 0x1B) 3) + $strSize + $blobSize }
            0x0B { 2 + (Get-CodedIndexSize @(0x04, 0x08, 0x17) 2) + $blobSize }
            0x0C { (Get-CodedIndexSize $HasCustomAttribute 5) + (Get-CodedIndexSize @(0x06, 0x0A, 0x00, 0x00) 3) + $blobSize }
            0x0D { (Get-CodedIndexSize @(0x04, 0x08) 1) + $blobSize }
            0x0E { 2 + (Get-CodedIndexSize @(0x02, 0x06, 0x20) 2) + $blobSize }
            0x0F { 6 + (Get-SimpleIndexSize 0x02) }
            0x10 { 4 + (Get-SimpleIndexSize 0x04) }
            0x11 { $blobSize }
            0x12 { (Get-SimpleIndexSize 0x02) + (Get-SimpleIndexSize 0x14) }
            0x13 { Get-SimpleIndexSize 0x14 }
            0x14 { 2 + $strSize + (Get-CodedIndexSize $TypeDefOrRef 2) }
            0x15 { (Get-SimpleIndexSize 0x02) + (Get-SimpleIndexSize 0x17) }
            0x16 { Get-SimpleIndexSize 0x17 }
            0x17 { 2 + $strSize + $blobSize }
            0x18 { 2 + (Get-SimpleIndexSize 0x06) + (Get-CodedIndexSize @(0x14, 0x17) 1) }
            0x19 { (Get-SimpleIndexSize 0x02) + 2 * (Get-CodedIndexSize @(0x06, 0x0A) 1) }
            0x1A { $strSize }
            0x1B { $blobSize }
            0x1C { 2 + (Get-CodedIndexSize @(0x04, 0x06) 1) + $strSize + (Get-SimpleIndexSize 0x1A) }
            0x1D { 4 + (Get-SimpleIndexSize 0x04) }
            0x1E { 8 }
            0x1F { 4 }
            0x20 { 16 + $blobSize + 2 * $strSize }
            0x21 { 4 }
            0x22 { 12 }
            0x23 { 12 + $blobSize + 2 * $strSize + $blobSize }
            0x24 { 4 + (Get-SimpleIndexSize 0x23) }
            0x25 { 12 + (Get-SimpleIndexSize 0x23) }
            0x26 { 4 + $strSize + $blobSize }
            0x27 { 8 + 2 * $strSize + (Get-CodedIndexSize @(0x26, 0x23, 0x27) 2) }
            0x28 { 8 + $strSize + (Get-CodedIndexSize @(0x26, 0x23, 0x27) 2) }
            0x29 { 2 * (Get-SimpleIndexSize 0x02) }
            0x2A { 4 + (Get-CodedIndexSize @(0x02, 0x06) 1) + $strSize }
            0x2B { (Get-CodedIndexSize @(0x06, 0x0A) 1) + $blobSize }
            0x2C { (Get-SimpleIndexSize 0x2A) + (Get-CodedIndexSize $TypeDefOrRef 2) }
            default { throw "Unsupported metadata table 0x{0:X2}" -f $Table }
        }
    }

    $tableOffset = @{}
    $cursor = $rowPtr
    foreach ($t in $presentTables) {
        $tableOffset[$t] = $cursor
        $cursor += [int]$rowCounts[$t] * [int](Get-RowSize $t)
    }

    function Get-HeapString([uint32]$Index) {
        $start = $stringsHeap + [int]$Index
        $end = $start
        while ($Bytes[$end] -ne 0) { $end++ }
        [Text.Encoding]::UTF8.GetString($Bytes, $start, $end - $start)
    }
    function Get-BlobBytes([uint32]$Index) {
        $start = $blobHeap + [int]$Index
        $b0 = $Bytes[$start]
        if ($b0 -lt 0x80) { $len = $b0; $data = $start + 1 }
        elseif (($b0 -band 0xC0) -eq 0x80) { $len = ((($b0 -band 0x3F) -shl 8) -bor $Bytes[$start + 1]); $data = $start + 2 }
        else { $len = [int]([BitConverter]::ToUInt32($Bytes, $start) -band 0x1FFFFFFF); $data = $start + 4 }
        return , $Bytes[$data..($data + $len - 1)]
    }

    if (-not $rowCounts.ContainsKey(0x02)) { throw 'TypeDef table missing' }
    if (-not $rowCounts.ContainsKey(0x06)) { throw 'MethodDef table missing' }

    $tdBase = $tableOffset[0x02]
    $tdSize = [int](Get-RowSize 0x02)
    $mdBase = $tableOffset[0x06]
    $mdSize = [int](Get-RowSize 0x06)
    $methodCount = [int]$rowCounts[0x06]

    $targets = New-Object System.Collections.ArrayList
    for ($row = 1; $row -le [int]$rowCounts[0x02]; $row++) {
        $off = $tdBase + ($row - 1) * $tdSize
        $nameIdx = 0
        if ($strSize -eq 4) { $nameIdx = [BitConverter]::ToUInt32($Bytes, $off + 4) } else { $nameIdx = [BitConverter]::ToUInt16($Bytes, $off + 4) }
        if ((Get-HeapString $nameIdx) -ne $TypeName) { continue }

        $tdorSize = Get-CodedIndexSize $TypeDefOrRef 2
        $fieldSize = Get-SimpleIndexSize 0x04
        $methodSize = Get-SimpleIndexSize 0x06
        $methodListOff = $off + 4 + 2 * $strSize + $tdorSize + $fieldSize
        $firstMethod = 0
        if ($methodSize -eq 4) { $firstMethod = [BitConverter]::ToUInt32($Bytes, $methodListOff) } else { $firstMethod = [BitConverter]::ToUInt16($Bytes, $methodListOff) }
        if ($row -lt $rowCounts[0x02]) {
            $nextOff = $tdBase + $row * $tdSize
            $nextListOff = $nextOff + 4 + 2 * $strSize + $tdorSize + $fieldSize
            if ($methodSize -eq 4) { $lastMethod = [BitConverter]::ToUInt32($Bytes, $nextListOff) - 1 } else { $lastMethod = [BitConverter]::ToUInt16($Bytes, $nextListOff) - 1 }
        } else {
            $lastMethod = $methodCount
        }

        for ($m = $firstMethod; $m -le $lastMethod; $m++) {
            if ($m -lt 1 -or $m -gt $methodCount) { continue }
            $mOff = $mdBase + ($m - 1) * $mdSize
            $rva = [BitConverter]::ToUInt32($Bytes, $mOff)
            $implFlags = [BitConverter]::ToUInt16($Bytes, $mOff + 4)
            $mNameIdx = 0
            if ($strSize -eq 4) { $mNameIdx = [BitConverter]::ToUInt32($Bytes, $mOff + 8) } else { $mNameIdx = [BitConverter]::ToUInt16($Bytes, $mOff + 8) }
            $sigIdx = 0
            if ($strSize -eq 4) { $sigIdx = [BitConverter]::ToUInt32($Bytes, $mOff + 8 + $strSize) } else { $sigIdx = [BitConverter]::ToUInt16($Bytes, $mOff + 8 + $strSize) }

            if ((Get-HeapString $mNameIdx) -ne $MethodName) { continue }

            $returnsBool = $false
            try {
                $sig = Get-BlobBytes $sigIdx
                $retPos = 2
                if (($sig[0] -band 0x10) -ne 0) { $retPos = 3 }
                $returnsBool = ($sig[$retPos] -eq 0x02)
            } catch { }

            $target = @{
                MethodRow      = $m
                MethodRva      = $rva
                ImplFlags      = $implFlags
                ReturnsBool    = $returnsBool
                HeaderKind     = $null
                BodyOffset     = -1
                AlreadyPatched = $false
            }
            if ($rva -ne 0) {
                $bodyOff = Convert-RvaToOffset $rva
                $first = $Bytes[$bodyOff]
                if (($first -band 0x3) -eq 2) {
                    $target.HeaderKind = 'tiny'
                    $target.BodyOffset = $bodyOff + 1
                } elseif (($first -band 0x3) -eq 3) {
                    $target.HeaderKind = 'fat'
                    $u16 = [BitConverter]::ToUInt16($Bytes, $bodyOff)
                    $target.BodyOffset = $bodyOff + (($u16 -shr 12) * 4)
                } else {
                    $target.HeaderKind = 'unknown'
                }
                if ($target.BodyOffset -ge 0 -and $Bytes[$target.BodyOffset] -eq 0x17 -and $Bytes[$target.BodyOffset + 1] -eq 0x2A) {
                    $target.AlreadyPatched = $true
                }
            }
            [void]$targets.Add($target)
        }
    }
    return , $targets
}

function Save-Backup {
    param([string]$Path, [byte[]]$OriginalBytes)
    $dll = Get-Item -Path $Path
    $version = $dll.VersionInfo.FileVersion
    if (-not $version) { $version = $dll.LastWriteTimeUtc.ToString('yyyyMMddHHmmss') }
    $safe = ($version -replace '[^A-Za-z0-9._-]', '_')
    $dir = Join-Path $BackupRoot $safe
    if (-not (Test-Path (Join-Path $dir "$($dll.Name).orig"))) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $dir "$($dll.Name).orig"), $OriginalBytes)
        Write-Log ("Backup saved: {0}" -f (Join-Path $dir "$($dll.Name).orig"))
    }
}

function Get-BackupPath {
    param([string]$Path)
    $dll = Get-Item -Path $Path
    $version = $dll.VersionInfo.FileVersion
    if (-not $version) { $version = $dll.LastWriteTimeUtc.ToString('yyyyMMddHHmmss') }
    $safe = ($version -replace '[^A-Za-z0-9._-]', '_')
    return (Join-Path (Join-Path $BackupRoot $safe) "$($dll.Name).orig")
}

function Test-NeedsElevation {
    param([string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    return $full.StartsWith(${env:ProgramFiles}, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-Patch {
    $dllPath = Get-ClientDllPath
    if (-not (Test-Path $dllPath)) { throw "Client assembly not found: $dllPath" }
    if ((Test-NeedsElevation -Path $dllPath) -and -not (Test-IsElevated)) {
        throw 'Patching the installed client requires elevation (run as Administrator).'
    }
    Write-Log ("Target: {0}" -f $dllPath)

    $bytes = [IO.File]::ReadAllBytes($dllPath)
    $targets = Get-PatchTargets -Bytes $bytes -TypeName $TargetTypeName -MethodName $TargetMethodName

    $patchable = @($targets | Where-Object { $_.MethodRva -ne 0 -and $_.ReturnsBool -and (($_.ImplFlags -band 0x3) -eq 0) -and $_.HeaderKind -in 'tiny', 'fat' })
    if ($patchable.Count -eq 0) {
        throw ("No patchable {0}.{1} method found. The client layout may have changed; reinstalling this tool will not help until it is updated." -f $TargetTypeName, $TargetMethodName)
    }

    $changed = $false
    foreach ($t in $patchable) {
        if ($t.AlreadyPatched) {
            Write-Log ("Method row {0}: already patched, skipping." -f $t.MethodRow)
            continue
        }
        if (-not $changed) { Save-Backup -Path $dllPath -OriginalBytes $bytes }
        $off = $t.BodyOffset
        if ($t.HeaderKind -eq 'tiny') {
            $bodyLen = $bytes[$off - 1] -shr 2
            if ($bodyLen -lt 2) { throw ("Method row {0}: body too small to patch" -f $t.MethodRow) }
            $bytes[$off - 1] = 0x0A
        }
        $bytes[$off] = 0x17
        $bytes[$off + 1] = 0x2A
        $changed = $true
        Write-Log ("Method row {0}: body rewritten to 'ldc.i4.1; ret' (always true)." -f $t.MethodRow)
    }

    if ($changed) {
        try {
            [IO.File]::WriteAllBytes($dllPath, $bytes)
            Write-Log "Patch written successfully."
        } catch [System.IO.IOException] {
            throw "Could not write the assembly (it is probably locked by a running Proton VPN client). Close the client and retry: $_"
        }
    } else {
        Write-Log "Nothing to do: already patched."
    }
}

function Invoke-Restore {
    $dllPath = Get-ClientDllPath
    if ((Test-NeedsElevation -Path $dllPath) -and -not (Test-IsElevated)) {
        throw 'Restoring the installed client requires elevation (run as Administrator).'
    }
    $backup = Get-BackupPath -Path $dllPath
    if (-not (Test-Path $backup)) { throw "No backup found for this client version: $backup" }
    try {
        Copy-Item -Force -Path $backup -Destination $dllPath
        Write-Log "Original assembly restored from $backup"
    } catch [System.IO.IOException] {
        throw "Could not restore (file locked by a running Proton VPN client). Close the client and retry: $_"
    }
}

function Show-Status {
    $dllPath = Get-ClientDllPath
    if (-not (Test-Path $dllPath)) { Write-Log "Client assembly not found: $dllPath"; return }
    $bytes = [IO.File]::ReadAllBytes($dllPath)
    $targets = Get-PatchTargets -Bytes $bytes -TypeName $TargetTypeName -MethodName $TargetMethodName
    $dll = Get-Item $dllPath
    Write-Log ("Client dll : {0} (FileProduct version {1})" -f $dllPath, $dll.VersionInfo.FileVersion)
    if ($targets.Count -eq 0) {
        Write-Log ("No {0}.{1} found in this build." -f $TargetTypeName, $TargetMethodName)
        return
    }
    foreach ($t in $targets) {
        $state = switch ($true) {
            { $t.MethodRva -eq 0 } { 'abstract/no-body - not patchable'; break }
            { -not $t.ReturnsBool } { 'unexpected return type - refused'; break }
            { ($t.ImplFlags -band 0x3) -ne 0 } { 'native/runtime impl - refused'; break }
            { $t.HeaderKind -notin 'tiny', 'fat' } { 'unknown method header - refused'; break }
            { $t.AlreadyPatched } { 'PATCHED (always returns true)'; break }
            default { 'original (cooldown enforced)' }
        }
        Write-Log ("  {0}.{1} [row {2}]: {3}" -f $TargetTypeName, $TargetMethodName, $t.MethodRow, $state)
    }
    $backup = Get-BackupPath -Path $dllPath
    Write-Log ("Backup present: {0}" -f (Test-Path $backup))
}

switch ($Action) {
    'Patch' { Invoke-Patch }
    'Restore' { Invoke-Restore }
    'Status' { Show-Status }
}
