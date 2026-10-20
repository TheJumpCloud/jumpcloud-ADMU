<#
Datto RMM component. One script for the whole JumpCloud ADMU workflow on a device.
The first log line prints $ScriptVersion, so you can confirm Datto runs this copy.

Mode (Datto string variable)
  Diagnose   Default. Read-only. Classifies every user and says what the next step is.
  Remediate  Fixes what is safe to fix. Removes a stray ADMU account and .000 profile left by
             a failed run, and repairs profile permissions on finished migrations.
  Migrate    Does Remediate, then migrates each ready user from the CSV with ADMU.

DryRun (Datto string variable)
  Anything except "false" means report the plan only. Set "false" to apply changes.

States the script reports
  Ready                 Domain profile intact. Can be migrated.
  StrayPreSwap          Failed run stopped before the profile swap. Cleanup fixes it.
  StrayNoProfile        ADMU account with no profile. Cleanup removes the account.
  MarkerStale           The domain hive still has the HKCU\Software\JCADMU key from a failed run.
                        ADMU then logs "The Key Already Exists", keeps a handle open, and cannot
                        unload the hive. ClearMarker backs up and deletes the key.
  NeedsPerms            Migration finished but the user lacks access. Permission repair fixes it.
  Migrated              Finished and access is fine.
  PostSwapDomainJoined  Profile swap happened and the machine is still on the domain. Manual.
                        If the user cannot sign in, run Start-Reversion. Not automated.
  NameCollision         A local account with that name exists and ADMU did not create it. Manual.
  NoProfile             No domain profile for that user on this device.
  NeedsReview           A safety check failed. The detail says which one.

Diagnose briefly loads each user's NTUSER.DAT offline to look for that key. It skips users who
are signed in. ClearMarker saves a copy of the hive and of the key in
C:\ProgramData\ADMU-Unified\hive-backups first.

Remediate and Migrate also tidy each Ready user: leftover NTUSER.DAT.BAK and UsrClass.dat.bak files
and .000 style folders that no profile uses are moved into C:\ProgramData\ADMU-Unified, not deleted.

Before any change it also looks for hives that an earlier ADMU run left loaded under HKU (names
ending _admu). They lock their files and make the next run fail at the registry backup step.
Remediate and Migrate unload them. If any stay loaded, Migrate refuses to start until the device
restarts. After a failed ADMU run, the runner unloads the hives ADMU left behind.

Migrate logs off every session first. Only the profiles being migrated must unload before ADMU
starts. Any other signed-in profile, such as an admin account, is logged off but does not block
the run, and its processes are not stopped.

Migrate runs ADMU in a scheduled task as SYSTEM, so it does not depend on the Datto job staying
alive. The component waits for the result and prints progress. Migrate refuses to start unless
every CSV user for the device is Ready, because leaving the domain strands any profile that is left.

Datto variables (all optional strings)
  Mode              Diagnose, Remediate, or Migrate. Default Diagnose.
  DryRun            Default true.
  TargetUsers       Comma-separated usernames, or ALL. Default ALL.
  ForceLogoff       true logs users off before a permission repair. Default false.
  RebootIfNeeded    true restarts in 5 minutes if a permission repair is blocked by a signed-in
                    user, and registers a startup task to finish. Default false.
  CsvName           Wave CSV attached to the component. Needed for Migrate.
  JumpCloudAPIKey   Needed for Migrate. Leave blank to use system context binding instead.
  JumpCloudOrgID    Needed with an MTP API key.

Exit code 1 means at least one user is Failed or NeedsReview. Otherwise 0.
Logs are in C:\ProgramData\ADMU-Unified.
#>
[CmdletBinding()]
param(
    [string]$Mode = $env:Mode,
    [string]$DryRun = $env:DryRun,
    [string]$TargetUsers = $env:TargetUsers,
    [string]$ForceLogoff = $env:ForceLogoff,
    [string]$RebootIfNeeded = $env:RebootIfNeeded,
    [string]$CsvName = $env:CsvName,
    [string]$JumpCloudAPIKey = $env:JumpCloudAPIKey,
    [string]$JumpCloudOrgID = $env:JumpCloudOrgID,
    [switch]$Resume
)

$ScriptVersion = '2026-10-20 r6'

# Migration settings. Edit here, not in Datto.
# Change TempPassword. It has the same placeholder default as 3_ADMU_Invoke.ps1. With JumpCloud binding, the JumpCloud
# password replaces it.
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$RestartAfterMigrate = $true
$UpdateHomePath = $false
$PrimaryUser = $true
$BindAsAdmin = $false
$SetDefaultWindowsUser = $true
$RemoveMDM = $false
$SetFullPermission = $true
$BlockAccountLogin = $false
$PollMinutes = 25

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$taskResume = 'ADMU-Unified-Resume'
$taskMigrate = 'ADMU-Unified-Migrate'
$workDir = Join-Path -Path $env:ProgramData -ChildPath 'ADMU-Unified'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null
$logFile = Join-Path -Path $workDir -ChildPath ('unified-{0}.log' -f (Get-Date -Format 'yyyyMMdd'))
$usersRoot = Join-Path -Path $env:SystemDrive -ChildPath 'Users'
$plRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$jcConf = 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
$jcKey = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
$exePath = Join-Path -Path $env:SystemRoot -ChildPath 'Temp\gui_jcadmu.exe'

# ---------------------------------------------------------------- helpers
function ConvertTo-Bool {
    param([string]$Value, [bool]$Default)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    return ($Value.Trim() -match '^(true|1|yes|y)$')
}

function Write-Log {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

function Get-ProfileListEntries {
    foreach ($item in @(Get-ChildItem -Path $plRoot -ErrorAction SilentlyContinue)) {
        $n = $item.PSChildName
        if ($n -like 'S-1-5-21-*') {
            $p = Get-ItemProperty -LiteralPath $item.PSPath
            $bare = $n -replace '\.bak$', ''
            $kind = 'Domain'
            if ($script:localSids -contains $bare) { $kind = 'Local' }
            [pscustomobject]@{ Key = $n; Sid = $bare; IsBak = [bool]($n -like '*.bak'); Kind = $kind; Path = $p.ProfileImagePath }
        }
    }
}

function Update-Data {
    $script:allLocal = @(Get-LocalUser)
    $script:localSids = @($script:allLocal | ForEach-Object { $_.SID.Value })
    $script:pl = @(Get-ProfileListEntries)
}

function Test-ProfileLoaded {
    param([string]$Sid)
    $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter ("SID='{0}'" -f $Sid) -ErrorAction SilentlyContinue
    return [bool]($profile -and $profile.Loaded)
}

function Stop-UserSession {
    param([string]$UserName)
    $lines = @(quser 2>$null | Select-Object -Skip 1)
    foreach ($line in $lines) {
        $parts = ($line -replace '^\s*>?\s*', '') -split '\s+'
        if ($parts[0] -ieq $UserName) {
            $id = $parts[1..($parts.Count - 1)] | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
            if ($id) { logoff.exe $id }
        }
    }
}

function Test-UserAccess {
    param([string]$Path, [string]$Sid)
    $need = [System.Security.AccessControl.FileSystemRights]::Modify
    foreach ($target in @($Path, (Join-Path -Path $Path -ChildPath 'Desktop'))) {
        if (-not (Test-Path -LiteralPath $target)) { continue }
        try { $acl = Get-Acl -LiteralPath $target -ErrorAction Stop } catch { return $false }
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference.Value -eq $Sid -and
                (($_.FileSystemRights -band $need) -eq $need)
            })
        if ($rules.Count -eq 0) { return $false }
    }
    return $true
}

function Invoke-Native {
    param([string]$Exe, [string[]]$Arguments, [string]$LogFile)
    Add-Content -Path $LogFile -Value ('[{0}] {1} {2}' -f (Get-Date -Format 'HH:mm:ss'), $Exe, ($Arguments -join ' '))
    & $Exe @Arguments 2>&1 |
        Where-Object { "$_" -match 'ERROR|denied|Failed|failed' } |
        Out-File -FilePath $LogFile -Append -Encoding utf8
    return $LASTEXITCODE
}

function Test-HiveFile {
    param([string]$Folder)
    return [System.IO.File]::Exists((Join-Path -Path $Folder -ChildPath 'NTUSER.DAT'))
}

function Invoke-HiveUnload {
    param([string]$Mount)
    for ($i = 1; $i -le 3; $i++) {
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        $null = & reg.exe unload ('HKU\{0}' -f $Mount) 2>&1
        if ($LASTEXITCODE -eq 0) { return $true }
        Start-Sleep -Seconds 2
    }
    Write-Log ('Warning. Could not unload HKU\{0}. A restart clears it.' -f $Mount)
    return $false
}

function Get-LeftoverAdmuHives {
    # reg.exe instead of the registry provider, so this process holds no handle on the hives.
    $names = @()
    foreach ($line in @(& reg.exe query HKU 2>$null)) {
        if ("$line" -match '^HKEY_USERS\\(?<n>\S+)\s*$') {
            $n = $Matches['n']
            if ($n -match '_admu$|^ADMU_MARKER_') { $names += $n }
        }
    }
    return $names
}

function Get-LeftoverFiles {
    param([string]$Folder)
    $a = @(Get-ChildItem -LiteralPath $Folder -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(NTUSER_premarker_|NTUSER\.DAT\.BAK)' })
    $cls = Join-Path -Path $Folder -ChildPath 'AppData\Local\Microsoft\Windows'
    $b = @(Get-ChildItem -LiteralPath $cls -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^UsrClass\.dat\.bak' })
    return @($a + $b)
}

function Get-OrphanSiblings {
    param([string]$Folder)
    $leaf = Split-Path -Path $Folder -Leaf
    $parent = Split-Path -Path $Folder -Parent
    return @(Get-ChildItem -LiteralPath $parent -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match ('^' + [regex]::Escape($leaf) + '\.\d{3}$') } |
        Where-Object { $full = $_.FullName; @($script:pl | Where-Object { $_.Path -ieq $full }).Count -eq 0 })
}

function Protect-BackupFolder {
    param([string]$Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

function Clear-LeftoverAdmuHives {
    if (@(Get-Process -Name 'gui_jcadmu' -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-Log 'gui_jcadmu.exe is running, so leftover hives were not touched.'
        return
    }
    foreach ($n in @(Get-LeftoverAdmuHives)) {
        if (Invoke-HiveUnload -Mount $n) { Write-Log ('Unloaded leftover hive HKU\{0}.' -f $n) }
    }
}

function ConvertFrom-RegQueryMarker {
    param([string[]]$Lines)
    $found = [pscustomobject]@{ Found = $false; KeyPath = ''; Value = '' }
    $current = ''
    foreach ($line in $Lines) {
        $text = "$line"
        if ($text -match '^HKEY_') { $current = $text.Trim() }
        elseif ($text -match '^\s+PreviousSID\s+REG_\w+\s+(?<v>\S+)') {
            $found.Found = $true
            $found.KeyPath = $current
            $found.Value = $Matches['v']
            break
        }
    }
    return $found
}

function Get-PreviousSidMarker {
    # Reports whether the hive still has HKCU\Software\JCADMU, and its PreviousSID if any.
    param([string]$Folder, [string]$Sid)
    $result = [pscustomobject]@{ Checked = $false; Found = $false; KeyPath = ''; Value = '' }
    $hive = Join-Path -Path $Folder -ChildPath 'NTUSER.DAT'
    if (-not (Test-HiveFile -Folder $Folder)) { return $result }
    if ($Sid -and (Test-ProfileLoaded -Sid $Sid)) { return $result }
    $mount = 'ADMU_MARKER_CHECK'
    $loaded = $false
    try {
        $null = & reg.exe load ('HKU\{0}' -f $mount) $hive 2>&1
        if ($LASTEXITCODE -ne 0) { return $result }
        $loaded = $true
        $result.Checked = $true
        $key = 'HKU\{0}\Software\JCADMU' -f $mount
        $out = @(& reg.exe query $key 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $result.Found = $true
            $result.KeyPath = $key
            $parsed = ConvertFrom-RegQueryMarker -Lines $out
            if ($parsed.Found) { $result.Value = $parsed.Value }
        }
    } finally {
        if ($loaded) { [void](Invoke-HiveUnload -Mount $mount) }
    }
    return $result
}

function Invoke-MarkerClear {
    # Backs up the hive and the JCADMU key, then deletes the key.
    param($Row)
    $st = $Row.St
    $folder = $st.BasePath
    $sid = $st.DomainSid
    $name = $Row.S.Name
    if (Test-ProfileLoaded -Sid $sid) {
        return [pscustomobject]@{ Ok = $false; Detail = 'The profile is loaded. Sign the user out and run again.' }
    }
    $bdir = Join-Path -Path $workDir -ChildPath 'hive-backups'
    Protect-BackupFolder -Path $bdir
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $hive = Join-Path -Path $folder -ChildPath 'NTUSER.DAT'
    $hiveCopy = Join-Path -Path $bdir -ChildPath ('{0}-NTUSER-{1}.DAT' -f $name, $ts)
    $regCopy = Join-Path -Path $bdir -ChildPath ('{0}-JCADMU-{1}.reg' -f $name, $ts)
    try { Copy-Item -LiteralPath $hive -Destination $hiveCopy -Force -ErrorAction Stop }
    catch { return [pscustomobject]@{ Ok = $false; Detail = ('Could not back up the hive. {0}' -f $_.Exception.Message) } }

    $mount = 'ADMU_MARKER_FIX'
    $loaded = $false
    try {
        $null = & reg.exe load ('HKU\{0}' -f $mount) $hive 2>&1
        if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ Ok = $false; Detail = 'Could not load the hive.' } }
        $loaded = $true
        $key = 'HKU\{0}\Software\JCADMU' -f $mount
        $out = @(& reg.exe query $key 2>&1)
        if ($LASTEXITCODE -ne 0) { return [pscustomobject]@{ Ok = $true; Detail = 'No JCADMU key found. Nothing to clear.' } }
        $parsed = ConvertFrom-RegQueryMarker -Lines $out
        if ($parsed.Found -and $parsed.Value -ne $sid) {
            return [pscustomobject]@{ Ok = $false; Detail = ('PreviousSID is {0}, not the user''s own SID. Not clearing it.' -f $parsed.Value) }
        }
        $null = & reg.exe export $key $regCopy /y 2>&1
        $null = & reg.exe delete $key /f 2>&1
        $null = & reg.exe query $key 2>&1
        if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Ok = $false; Detail = 'The JCADMU key is still present after the delete.' } }
        return [pscustomobject]@{ Ok = $true; Detail = ('Removed the leftover JCADMU key. Backups: {0} and {1}.' -f $hiveCopy, $regCopy) }
    } finally {
        if ($loaded) { [void](Invoke-HiveUnload -Mount $mount) }
    }
}

function Invoke-ProfileTidy {
    # Moves leftover .BAK hive files and unused .000 style folders out of the way.
    param($Row)
    $st = $Row.St
    $name = $Row.S.Name
    if (Test-ProfileLoaded -Sid $st.DomainSid) {
        return [pscustomobject]@{ Ok = $false; Detail = 'The profile is loaded. Sign the user out and run again.' }
    }
    $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
    $fdir = Join-Path -Path $workDir -ChildPath ('hive-backups\{0}-leftovers-{1}' -f $name, $ts)
    $qdir = Join-Path -Path $workDir -ChildPath ('quarantine\{0}-{1}' -f $name, $ts)
    Protect-BackupFolder -Path (Join-Path -Path $workDir -ChildPath 'hive-backups')
    Protect-BackupFolder -Path (Join-Path -Path $workDir -ChildPath 'quarantine')
    $problems = @()
    $files = @(Get-LeftoverFiles -Folder $st.BasePath)
    if ($files.Count -gt 0) { New-Item -ItemType Directory -Path $fdir -Force | Out-Null }
    foreach ($f in $files) {
        try { Move-Item -LiteralPath $f.FullName -Destination (Join-Path -Path $fdir -ChildPath $f.Name) -Force -ErrorAction Stop }
        catch { $problems += ('{0}: {1}' -f $f.Name, $_.Exception.Message) }
    }
    $folders = @(Get-OrphanSiblings -Folder $st.BasePath)
    if ($folders.Count -gt 0) { New-Item -ItemType Directory -Path $qdir -Force | Out-Null }
    foreach ($d in $folders) {
        try { Move-Item -LiteralPath $d.FullName -Destination (Join-Path -Path $qdir -ChildPath $d.Name) -Force -ErrorAction Stop }
        catch { $problems += ('{0}: {1}' -f $d.Name, $_.Exception.Message) }
    }
    if ($problems.Count -gt 0) {
        return [pscustomobject]@{ Ok = $false; Detail = ('Could not move: {0}. Restart the device and run again.' -f ($problems -join '; ')) }
    }
    return [pscustomobject]@{ Ok = $true; Detail = ('Moved {0} leftover files to {1} and {2} unused folders to {3}.' -f $files.Count, $fdir, $folders.Count, $qdir) }
}

function Find-CsvPath {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    if ([System.IO.Path]::IsPathRooted($Name) -and (Test-Path -LiteralPath $Name)) { return $Name }
    $dirs = @((Get-Location).Path, $PSScriptRoot, (Join-Path -Path $env:SystemRoot -ChildPath 'Temp')) | Where-Object { $_ }
    foreach ($d in $dirs) {
        $c = Join-Path -Path $d -ChildPath $Name
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

# ---------------------------------------------------------------- state classification
function Get-SubjectState {
    param($S)
    $name = $S.Name
    $o = [pscustomobject]@{ State = ''; Plan = 'None'; Detail = ''; LocalAcct = $null; LocalPath = $null; BasePath = $null; DomainSid = $S.Sid; Tidy = $false }

    $local = $script:allLocal | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
    if ($local) {
        $o.LocalAcct = $local
        if ($local.Description -notlike '*ADMU*') {
            $o.State = 'NameCollision'; $o.Plan = 'Manual'
            $o.Detail = 'A local account with this name exists and ADMU did not create it.'
            return $o
        }
        $lsid = $local.SID.Value
        $lkey = $script:pl | Where-Object { $_.Sid -eq $lsid -and -not $_.IsBak } | Select-Object -First 1
        if (-not $lkey -or [string]::IsNullOrWhiteSpace($lkey.Path)) {
            $o.State = 'StrayNoProfile'; $o.Plan = 'Cleanup'
            $o.Detail = 'ADMU account with no profile entry. The run failed before the profile was created.'
            return $o
        }
        $o.LocalPath = $lkey.Path
        $leaf = Split-Path -Path $lkey.Path -Leaf
        if ($leaf -match '^(?<base>.+)\.\d{3}$') {
            $base = Join-Path -Path $script:usersRoot -ChildPath $Matches['base']
            $o.BasePath = $base
            if (-not (Test-HiveFile -Folder $base)) {
                $o.State = 'NeedsReview'; $o.Plan = 'Manual'
                $o.Detail = ('Base folder {0} is missing or has no NTUSER.DAT.' -f $base)
                return $o
            }
            $mapped = @($script:pl | Where-Object { $_.Kind -eq 'Domain' -and -not $_.IsBak -and $_.Path -ieq $base })
            if ($mapped.Count -ne 1) {
                $o.State = 'NeedsReview'; $o.Plan = 'Manual'
                $o.Detail = ('Expected one domain SID mapped to {0}, found {1}.' -f $base, $mapped.Count)
                return $o
            }
            $o.DomainSid = $mapped[0].Sid
            if ($S.Sid -and $S.Sid -ne $mapped[0].Sid) {
                $o.State = 'NeedsReview'; $o.Plan = 'Manual'
                $o.Detail = 'The CSV SID does not match the domain SID mapped to the base folder.'
                return $o
            }
            if (@($script:pl | Where-Object { $_.Sid -eq $mapped[0].Sid -and $_.IsBak }).Count -gt 0) {
                $o.State = 'NeedsReview'; $o.Plan = 'Manual'
                $o.Detail = 'The domain SID has a .bak key, so the profile swap started. Use Start-Reversion.'
                return $o
            }
            $o.State = 'StrayPreSwap'; $o.Plan = 'Cleanup'
            $o.Detail = ('Failed run stopped before the swap. Stray profile {0}. Domain profile {1} intact.' -f $lkey.Path, $base)
            $m = Get-PreviousSidMarker -Folder $base -Sid $mapped[0].Sid
            if ($m.Found) { $o.Detail = '{0} The hive also has a leftover JCADMU key. It is removed after the cleanup.' -f $o.Detail }
            return $o
        }
        $o.BasePath = $lkey.Path
        if ($script:partOfDomain) {
            $o.State = 'PostSwapDomainJoined'; $o.Plan = 'Manual'
            $o.Detail = 'Profile swap happened and the machine is still domain joined. If the user cannot sign in, use Start-Reversion.'
            return $o
        }
        if (Test-UserAccess -Path $lkey.Path -Sid $lsid) {
            $o.State = 'Migrated'; $o.Plan = 'None'
            $o.Detail = 'Migration finished and the user has access.'
        } else {
            $o.State = 'NeedsPerms'; $o.Plan = 'RepairPerms'
            $o.Detail = 'Migration finished but the user lacks Modify access on the profile root or Desktop.'
        }
        return $o
    }

    $dsid = $S.Sid
    if (-not $dsid) {
        $cands = @($script:pl | Where-Object { $_.Kind -eq 'Domain' -and -not $_.IsBak -and (Split-Path -Path $_.Path -Leaf) -ieq $name })
        if ($cands.Count -eq 1) { $dsid = $cands[0].Sid }
    }
    if (-not $dsid) {
        $o.State = 'NoProfile'; $o.Plan = 'None'
        $o.Detail = 'No domain profile found for this user on this device.'
        return $o
    }
    $o.DomainSid = $dsid
    $dkey = $script:pl | Where-Object { $_.Sid -eq $dsid -and -not $_.IsBak -and $_.Kind -eq 'Domain' } | Select-Object -First 1
    if (-not $dkey) {
        $o.State = 'NeedsReview'; $o.Plan = 'Manual'
        $o.Detail = 'The domain SID is not in ProfileList. The CSV may be out of date.'
        return $o
    }
    if (@($script:pl | Where-Object { $_.Sid -eq $dsid -and $_.IsBak }).Count -gt 0) {
        $o.State = 'NeedsReview'; $o.Plan = 'Manual'
        $o.Detail = 'The domain SID has a .bak key but no ADMU account exists. Review by hand.'
        return $o
    }
    $o.BasePath = $dkey.Path
    if ((Split-Path -Path $dkey.Path -Leaf) -like 'TEMP*') {
        $o.State = 'NeedsReview'; $o.Plan = 'Manual'
        $o.Detail = 'The domain SID maps a TEMP profile.'
        return $o
    }
    if (-not (Test-HiveFile -Folder $dkey.Path)) {
        $o.State = 'NeedsReview'; $o.Plan = 'Manual'
        $o.Detail = ('No NTUSER.DAT in {0}.' -f $dkey.Path)
        return $o
    }
    $marker = Get-PreviousSidMarker -Folder $dkey.Path -Sid $dsid
    if ($marker.Found) {
        if ([string]::IsNullOrWhiteSpace($marker.Value) -or $marker.Value -eq $dsid) {
            $o.State = 'MarkerStale'; $o.Plan = 'ClearMarker'
            $o.Detail = 'The domain hive still has the JCADMU key from a failed run. ADMU cannot unload the hive while it is there.'
        } else {
            $o.State = 'NeedsReview'; $o.Plan = 'Manual'
            $o.Detail = ('The hive has PreviousSID {0}, a different SID. The user was migrated before.' -f $marker.Value)
        }
        return $o
    }
    $o.State = 'Ready'
    $note = ''
    if (-not $marker.Checked) { $note = ' JCADMU key not checked because the profile is loaded.' }
    $nFiles = @(Get-LeftoverFiles -Folder $dkey.Path).Count
    $nDirs = @(Get-OrphanSiblings -Folder $dkey.Path).Count
    if (($nFiles + $nDirs) -gt 0) {
        $o.Tidy = $true
        $note = '{0} Leftovers to move first: {1} files, {2} unused .000 style folders.' -f $note, $nFiles, $nDirs
    }
    if ($S.FromCsv) {
        $o.Plan = 'Migrate'
        $o.Detail = ('Domain profile {0} intact. Ready to migrate.{1}' -f $dkey.Path, $note)
    } else {
        $o.Plan = 'None'
        $o.Detail = ('Domain profile {0} intact. Not in the CSV, so Migrate skips it.{1}' -f $dkey.Path, $note)
    }
    return $o
}

# ---------------------------------------------------------------- remediation
function Invoke-StrayCleanup {
    param($Row)
    $st = $Row.St
    $acct = $st.LocalAcct
    $sid = $acct.SID.Value
    if (@(Get-Process -Name 'gui_jcadmu' -ErrorAction SilentlyContinue).Count -gt 0) {
        return [pscustomobject]@{ Ok = $false; Detail = 'gui_jcadmu.exe is running. A migration may be in progress.' }
    }
    if ($st.LocalPath -and (Test-ProfileLoaded -Sid $sid)) {
        return [pscustomobject]@{ Ok = $false; Detail = 'The stray profile is loaded. Restart the machine and run again.' }
    }
    Write-Log ('Removing ADMU account {0} and profile {1}.' -f $acct.Name, $st.LocalPath)
    if ($st.LocalPath) {
        $prof = Get-CimInstance -ClassName Win32_UserProfile -Filter ("SID='{0}'" -f $sid) -ErrorAction SilentlyContinue
        if ($prof -and $prof.LocalPath -ieq $st.LocalPath) {
            try { Remove-CimInstance -InputObject $prof -ErrorAction Stop } catch { Write-Log ('Profile removal error. {0}' -f $_.Exception.Message) }
        }
    }
    try { Remove-LocalUser -SID $acct.SID -ErrorAction Stop } catch { Write-Log ('Account removal error. {0}' -f $_.Exception.Message) }

    $accountGone = $true
    try { [void](Get-LocalUser -SID $acct.SID -ErrorAction Stop); $accountGone = $false } catch { $accountGone = $true }
    $folderGone = $true
    if ($st.LocalPath) { $folderGone = -not (Test-Path -LiteralPath $st.LocalPath) }
    $domainOk = $true
    if ($st.BasePath -and $st.LocalPath -ne $st.BasePath) {
        $domainOk = Test-HiveFile -Folder $st.BasePath
    }
    if ($accountGone -and $domainOk) {
        $d = 'Account removed. Domain profile intact.'
        if (-not $folderGone) { $d = '{0} Folder {1} is still on disk. Delete it by hand after a restart.' -f $d, $st.LocalPath }
        return [pscustomobject]@{ Ok = $true; Detail = $d }
    }
    return [pscustomobject]@{ Ok = $false; Detail = ('AccountGone={0} FolderGone={1} DomainProfileOk={2}' -f $accountGone, $folderGone, $domainOk) }
}

function Invoke-PermRepair {
    param($Row)
    $st = $Row.St
    $name = $Row.S.Name
    $sid = $st.LocalAcct.SID.Value
    $path = $st.LocalPath

    if (Test-ProfileLoaded -Sid $sid) {
        if ($script:logoff) {
            Write-Log ('Logging off {0}.' -f $name)
            Stop-UserSession -UserName $name
            $deadline = (Get-Date).AddSeconds(120)
            while ((Test-ProfileLoaded -Sid $sid) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
        }
        if (Test-ProfileLoaded -Sid $sid) {
            return [pscustomobject]@{ Ok = $false; Pending = $true; Detail = 'Profile is loaded. Needs the user signed out or a restart.' }
        }
    }
    $userLog = Join-Path -Path $workDir -ChildPath ('perm-{0}-{1}.log' -f $name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-Log ('Repairing permissions for {0} at {1}. Errors go to {2}.' -f $name, $path, $userLog)
    $steps = @(
        @{ Exe = 'takeown.exe'; Arguments = @('/F', $path, '/R', '/A', '/D', 'Y') },
        @{ Exe = 'icacls.exe'; Arguments = @($path, '/grant', ('*{0}:(OI)(CI)F' -f $sid), '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '/T', '/C', '/Q', '/L') },
        @{ Exe = 'icacls.exe'; Arguments = @($path, '/setowner', ('*{0}' -f $sid), '/T', '/C', '/Q', '/L') }
    )
    foreach ($step in $steps) {
        $code = Invoke-Native -Exe $step.Exe -Arguments $step.Arguments -LogFile $userLog
        Write-Log ('  {0} finished with exit code {1}' -f $step.Exe, $code)
    }
    if (Test-UserAccess -Path $path -Sid $sid) {
        return [pscustomobject]@{ Ok = $true; Pending = $false; Detail = ('Access verified. Details in {0}.' -f $userLog) }
    }
    return [pscustomobject]@{ Ok = $false; Pending = $false; Detail = ('Access check still fails after repair. See {0}.' -f $userLog) }
}

function Register-ResumeTask {
    param([string[]]$Users)
    $copy = Join-Path -Path $workDir -ChildPath 'ADMU-Unified.ps1'
    if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath)) {
        Write-Log 'Cannot register the startup task because the script path is unavailable. Rerun after the restart.'
        return $false
    }
    if ($PSCommandPath -ne $copy) { Copy-Item -LiteralPath $PSCommandPath -Destination $copy -Force }
    $argText = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Resume -Mode Remediate -DryRun false -TargetUsers "{1}" -ForceLogoff false -RebootIfNeeded false' -f $copy, ($Users -join ',')
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argText
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4)
    Register-ScheduledTask -TaskName $taskResume -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log ('Registered startup task {0} for: {1}' -f $taskResume, ($Users -join ', '))
    return $true
}

# ---------------------------------------------------------------- migration
function Get-AdmuExe {
    param([string]$Destination)
    $api = 'https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases/latest'
    $headers = @{ Accept = 'application/vnd.github.v3+json' }
    for ($i = 1; $i -le 3; $i++) {
        try {
            $rel = Invoke-RestMethod -Uri $api -Headers $headers -ErrorAction Stop
            $asset = $rel.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' } | Select-Object -First 1
            if (-not $asset) { throw 'gui_jcadmu.exe was not found in the latest release.' }
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $Destination -ErrorAction Stop
            if ($asset.digest -match '^sha256:(?<h>[0-9a-fA-F]+)$') {
                $actual = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash
                if ($actual -ne $Matches['h']) { throw 'SHA256 does not match the release digest.' }
            } else {
                Write-Log 'Warning. The release has no digest, so the SHA256 check was skipped.'
            }
            Write-Log ('Downloaded {0} {1}.' -f $asset.name, $rel.tag_name)
            return $true
        } catch {
            Write-Log ('Download attempt {0} failed. {1}' -f $i, $_.Exception.Message)
            if ($i -lt 3) { Start-Sleep -Seconds 20 }
        }
    }
    return $false
}

$runnerText = @'
param([Parameter(Mandatory = $true)][string]$JobFile)
$ErrorActionPreference = 'Continue'
$job = Get-Content -LiteralPath $JobFile -Raw | ConvertFrom-Json
$workDir = Split-Path -Path $JobFile -Parent
$statusFile = Join-Path -Path $workDir -ChildPath 'status.json'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path -Path $workDir -ChildPath ('migrate-{0}.log' -f $stamp)

function Write-Log {
    param([string]$Message)
    Add-Content -Path $log -Value ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
}
function Set-Status {
    param([string]$State, [string]$Detail)
    $obj = [ordered]@{ State = $State; Detail = $Detail; Time = (Get-Date).ToString('s'); Log = $log }
    ($obj | ConvertTo-Json) | Set-Content -Path $statusFile -Encoding UTF8
}
function Get-LoadedUserProfiles {
    Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.Loaded -and -not $_.Special }
}
function Clear-AdmuHives {
    # After ADMU exits, its own handles are gone, so the hives it left loaded can be unloaded.
    $left = @()
    foreach ($line in @(& reg.exe query HKU 2>$null)) {
        if ("$line" -notmatch '^HKEY_USERS\\(?<n>\S+)\s*$') { continue }
        $n = $Matches['n']
        if ($n -notmatch '_admu$') { continue }
        $ok = $false
        for ($i = 1; $i -le 3 -and -not $ok; $i++) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $null = & reg.exe unload ('HKU\{0}' -f $n) 2>&1
            if ($LASTEXITCODE -eq 0) { $ok = $true } else { Start-Sleep -Seconds 2 }
        }
        if ($ok) { Write-Log ('Unloaded leftover hive HKU\{0}.' -f $n) } else { $left += $n }
    }
    return $left
}
function Get-LoadedTargets {
    Get-LoadedUserProfiles | Where-Object { $targetSids -contains $_.SID }
}

try {
    Set-Status -State 'Running' -Detail 'Logging off users'
    Write-Log 'Runner started.'
    $lines = @(quser 2>$null | Select-Object -Skip 1)
    foreach ($line in $lines) {
        $parts = ($line -replace '^\s*>?\s*', '') -split '\s+'
        $id = $parts[1..($parts.Count - 1)] | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1
        if ($id) { Write-Log ('Logging off {0} (session {1})' -f $parts[0], $id); logoff.exe $id }
    }
    $targetSids = @($job.users | ForEach-Object { $_.sid })
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-LoadedTargets).Count -gt 0 -and $sw.Elapsed.TotalSeconds -lt 180) { Start-Sleep -Seconds 3 }
    $stuck = @(Get-LoadedTargets)
    if ($stuck.Count -gt 0) {
        $names = @(foreach ($p in $stuck) {
                try { ([Security.Principal.SecurityIdentifier]$p.SID).Translate([Security.Principal.NTAccount]).Value } catch { }
            })
        Write-Log ('Migrating profiles still loaded after 180 seconds ({0}). Stopping their processes.' -f ($names -join ', '))
        Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
            Where-Object { $names -contains $_.UserName } |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 15
    }
    $stuck = @(Get-LoadedTargets)
    if ($stuck.Count -gt 0) {
        $msg = 'Profiles being migrated are still loaded: {0}. Aborted before migration.' -f (($stuck | ForEach-Object { $_.LocalPath }) -join ', ')
        Write-Log $msg
        Set-Status -State 'Aborted' -Detail $msg
        return
    }
    $others = @(Get-LoadedUserProfiles)
    if ($others.Count -gt 0) {
        Write-Log ('Warning. Other profiles are still loaded and do not block the migration: {0}' -f (($others | ForEach-Object { $_.LocalPath }) -join ', '))
    }
    Write-Log 'The profiles being migrated are unloaded.'

    $users = @($job.users)
    $failed = @()
    for ($i = 0; $i -lt $users.Count; $i++) {
        $u = $users[$i]
        $isLast = ($i -eq ($users.Count - 1))
        $p = [ordered]@{
            JumpCloudUserName     = $u.name
            SelectedUserName      = $u.sid
            TempPassword          = $job.tempPassword
            UpdateHomePath        = [bool]$job.updateHomePath
            PrimaryUser           = [bool]$job.primaryUser
            BindAsAdmin           = [bool]$job.bindAsAdmin
            SetDefaultWindowsUser = [bool]$job.setDefaultWindowsUser
            LeaveDomain           = ($isLast -and [bool]$job.leaveDomain)
            RemoveMDM             = ($isLast -and [bool]$job.removeMDM)
            adminDebug            = $true
            ReportStatus          = $false
            BlockAccountLogin     = [bool]$job.blockAccountLogin
        }
        if ($job.useSystemContext) {
            $p['systemContextBinding'] = $true
            $p['JumpCloudUserID'] = $u.jcUserId
        } else {
            $p['AutoBindJCUser'] = $true
            $p['JumpCloudAPIKey'] = $job.apiKey
            if (-not [string]::IsNullOrWhiteSpace($job.orgId)) { $p['JumpCloudOrgID'] = $job.orgId }
        }
        if ($job.setFullPermission) { $p['SetFullPermission'] = $true }
        $argList = @(foreach ($k in $p.Keys) {
                $v = $p[$k]
                if ($v -is [bool]) { '-{0}:${1}' -f $k, $v.ToString().ToLower() } else { '-{0}:{1}' -f $k, $v }
            })

        $outFile = Join-Path -Path $workDir -ChildPath ('exe-{0}-{1}.log' -f $u.name, $stamp)
        Set-Status -State 'Running' -Detail ('Migrating {0}' -f $u.name)
        Write-Log ('Starting ADMU for {0}. Output goes to {1}.' -f $u.name, $outFile)
        & $job.exePath @argList 2>&1 | Out-File -FilePath $outFile -Encoding utf8
        $code = $LASTEXITCODE
        Write-Log ('ADMU exit code for {0}: {1}' -f $u.name, $code)
        Get-Content -Path $outFile -Tail 15 -ErrorAction SilentlyContinue | ForEach-Object { Write-Log ('  ' + $_) }
        if ($code -ne 0) { $failed += $u.name }
    }

    if ($failed.Count -gt 0) {
        $left = @(Clear-AdmuHives)
        if ($left.Count -eq 0) { $hiveNote = 'Leftover ADMU hives were unloaded, so a retry does not need a restart.' }
        else { $hiveNote = 'These hives would not unload, so restart before a retry: {0}.' -f ($left -join ', ') }
        Write-Log $hiveNote
        Set-Status -State 'Failed' -Detail ('ADMU failed for: {0}. {1} Run Remediate before retrying. See {2}.' -f ($failed -join ', '), $hiveNote, $log)
    } elseif ($job.restart) {
        Set-Status -State 'Succeeded' -Detail 'Migration finished. Restarting in 60 seconds.'
        Write-Log 'Restarting in 60 seconds.'
        Start-Sleep -Seconds 60
        Restart-Computer -Force
    } else {
        Set-Status -State 'Succeeded' -Detail 'Migration finished. A restart is required to finish leaving the domain.'
    }
} catch {
    Write-Log ('Runner error. {0}' -f $_.Exception.Message)
    Set-Status -State 'Failed' -Detail $_.Exception.Message
} finally {
    Remove-Item -LiteralPath $JobFile -Force -ErrorAction SilentlyContinue
}
'@

function Start-MigrationTask {
    param($Rows)
    $users = @($Rows | ForEach-Object { [pscustomobject]@{ name = $_.S.Name; sid = $_.St.DomainSid; jcUserId = $_.S.JcId } })
    $jobPath = Join-Path -Path $workDir -ChildPath 'job.json'
    $runnerPath = Join-Path -Path $workDir -ChildPath 'ADMU-Runner.ps1'
    $statusFile = Join-Path -Path $workDir -ChildPath 'status.json'

    # The job file holds the API key, so only SYSTEM and Administrators may read this folder.
    icacls.exe $workDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    Remove-Item -LiteralPath $statusFile -Force -ErrorAction SilentlyContinue
    Set-Content -Path $runnerPath -Value $runnerText -Encoding UTF8
    $job = [ordered]@{
        users             = $users
        exePath           = $exePath
        tempPassword      = $TempPassword
        updateHomePath    = $UpdateHomePath
        primaryUser       = $PrimaryUser
        bindAsAdmin       = $BindAsAdmin
        setDefaultWindowsUser = $SetDefaultWindowsUser
        leaveDomain       = $LeaveDomain
        removeMDM         = $RemoveMDM
        setFullPermission = $SetFullPermission
        blockAccountLogin = $BlockAccountLogin
        useSystemContext  = [string]::IsNullOrWhiteSpace($JumpCloudAPIKey)
        apiKey            = $JumpCloudAPIKey
        orgId             = $JumpCloudOrgID
        restart           = $RestartAfterMigrate
    }
    ($job | ConvertTo-Json -Depth 5) | Set-Content -Path $jobPath -Encoding UTF8

    $argText = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -JobFile "{1}"' -f $runnerPath, $jobPath
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argText
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)
    Register-ScheduledTask -TaskName $taskMigrate -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $taskMigrate
    Write-Log ('Started scheduled task {0}. It keeps running if this job ends.' -f $taskMigrate)

    $deadline = (Get-Date).AddMinutes($PollMinutes)
    $last = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 5
        $status = $null
        if (Test-Path -LiteralPath $statusFile) {
            try { $status = Get-Content -LiteralPath $statusFile -Raw | ConvertFrom-Json } catch { $status = $null }
        }
        if ($status) {
            $line = '{0}: {1}' -f $status.State, $status.Detail
            if ($line -ne $last) { Write-Log ('Migration task. {0}' -f $line); $last = $line }
            if ($status.State -in 'Succeeded', 'Failed', 'Aborted') {
                Unregister-ScheduledTask -TaskName $taskMigrate -Confirm:$false -ErrorAction SilentlyContinue
                return $status
            }
        }
    }
    return [pscustomobject]@{ State = 'Running'; Detail = ('Still running after {0} minutes. Check {1}\status.json.' -f $PollMinutes, $workDir); Log = '' }
}

# ---------------------------------------------------------------- settings
$modeName = 'Diagnose'
if (-not [string]::IsNullOrWhiteSpace($Mode)) {
    switch ($Mode.Trim().ToLower()) {
        'diagnose' { $modeName = 'Diagnose' }
        'remediate' { $modeName = 'Remediate' }
        'migrate' { $modeName = 'Migrate' }
        default { Write-Host ('Unknown Mode "{0}". Use Diagnose, Remediate, or Migrate.' -f $Mode); exit 1 }
    }
}
$dry = ConvertTo-Bool -Value $DryRun -Default $true
$logoff = ConvertTo-Bool -Value $ForceLogoff -Default $false
$reboot = ConvertTo-Bool -Value $RebootIfNeeded -Default $false
$apply = ($modeName -ne 'Diagnose') -and (-not $dry)

Write-Log ('Start. Version={0} Computer={1} Mode={2} DryRun={3} Resume={4}' -f $ScriptVersion, $env:COMPUTERNAME, $modeName, $dry, [bool]$Resume)
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
$partOfDomain = [bool]$cs.PartOfDomain
Write-Log ('Domain joined: {0}. Domain or workgroup: {1}' -f $partOfDomain, $cs.Domain)
if ($partOfDomain) {
    try { Write-Log ('Domain trust OK: {0}' -f (Test-ComputerSecureChannel -ErrorAction Stop)) }
    catch { Write-Log ('Domain trust check failed. {0} ADMU still migrates by SID.' -f $_.Exception.Message) }
}
Update-Data

# ---------------------------------------------------------------- CSV rows for this device
$csvRows = @()
$csvPath = Find-CsvPath -Name $CsvName
if ($csvPath) {
    $imported = @(Import-Csv -Path $csvPath)
    $needHeaders = 'SID', 'JumpCloudUserName', 'LocalComputerName', 'SerialNumber'
    $missing = @()
    if ($imported.Count -gt 0) { $missing = @($needHeaders | Where-Object { $imported[0].PSObject.Properties.Name -notcontains $_ }) }
    if ($missing.Count -gt 0) {
        Write-Log ('CSV is missing headers: {0}' -f ($missing -join ', '))
        exit 1
    }
    $hostName = $env:COMPUTERNAME
    $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    $csvRows = @($imported | Where-Object {
            $_.LocalComputerName -eq $hostName -and $_.SerialNumber -eq $serial -and -not [string]::IsNullOrWhiteSpace($_.JumpCloudUserName)
        })
    Write-Log ('CSV {0}. Rows for this device: {1}' -f $csvPath, $csvRows.Count)
} elseif (-not [string]::IsNullOrWhiteSpace($CsvName)) {
    Write-Log ('CSV not found: {0}' -f $CsvName)
}
if ($modeName -eq 'Migrate' -and $csvRows.Count -eq 0) {
    Write-Log 'Migrate needs a CSV with at least one row for this hostname and serial. Nothing to do.'
    exit 1
}

# ---------------------------------------------------------------- subjects
$subjects = [ordered]@{}
foreach ($row in $csvRows) {
    $subjects[$row.JumpCloudUserName.ToLower()] = [pscustomobject]@{ Name = $row.JumpCloudUserName; Sid = $row.SID; JcId = $row.JumpCloudUserID; FromCsv = $true }
}
foreach ($acct in $script:allLocal) {
    $rid = [int64]($acct.SID.Value.Split('-')[-1])
    if ($rid -ge 1000 -and $acct.Description -like '*ADMU*' -and -not $subjects.Contains($acct.Name.ToLower())) {
        $subjects[$acct.Name.ToLower()] = [pscustomobject]@{ Name = $acct.Name; Sid = $null; JcId = $null; FromCsv = $false }
    }
}
$wanted = @()
if (-not [string]::IsNullOrWhiteSpace($TargetUsers) -and $TargetUsers.Trim() -ne 'ALL') {
    $wanted = @($TargetUsers -split '[,;\s]+' | Where-Object { $_ })
    foreach ($n in $wanted) {
        if (-not $subjects.Contains($n.ToLower())) {
            $subjects[$n.ToLower()] = [pscustomobject]@{ Name = $n; Sid = $null; JcId = $null; FromCsv = $false }
        }
    }
}
$subjectList = @($subjects.Values)
if ($wanted.Count -gt 0) { $subjectList = @($subjectList | Where-Object { $wanted -contains $_.Name }) }

if ($subjectList.Count -eq 0) {
    Write-Log 'No users to look at. Nothing to do.'
    if ($Resume) { Unregister-ScheduledTask -TaskName $taskResume -Confirm:$false -ErrorAction SilentlyContinue }
    exit 0
}

# ---------------------------------------------------------------- classify
$rows = New-Object -TypeName System.Collections.ArrayList
foreach ($s in $subjectList) {
    $st = Get-SubjectState -S $s
    $result = 'ReadOnly'
    if ($modeName -ne 'Diagnose') { $result = 'DryRun' }
    [void]$rows.Add([pscustomobject]@{ S = $s; St = $st; Result = $result })
}

# Other domain profiles on the device. Leaving the domain strands them.
$subjectSids = @($rows | ForEach-Object { $_.St.DomainSid } | Where-Object { $_ })
$others = @($script:pl | Where-Object { $_.Kind -eq 'Domain' -and -not $_.IsBak -and $subjectSids -notcontains $_.Sid -and $_.Path -and (Test-Path -LiteralPath $_.Path) })
foreach ($o in $others) {
    $hive = Join-Path -Path $o.Path -ChildPath 'NTUSER.DAT'
    $written = 'unknown'
    if ([System.IO.File]::Exists($hive)) { $written = [System.IO.File]::GetLastWriteTime($hive).ToString('yyyy-MM-dd') }
    Write-Log ('Other domain profile on this device. {0} (NTUSER.DAT last written {1}). Leaving the domain strands it.' -f $o.Path, $written)
}

# ---------------------------------------------------------------- leftover hives
$hivesBlocked = $false
$leftover = @(Get-LeftoverAdmuHives)
if ($leftover.Count -gt 0) {
    Write-Log ('Leftover ADMU hives are still loaded under HKU. {0}' -f ($leftover -join ', '))
    Write-Log 'A loaded hive locks its file, and the next ADMU run then fails at the registry backup step.'
    if ($apply) {
        Clear-LeftoverAdmuHives
        if (@(Get-LeftoverAdmuHives).Count -gt 0) {
            $hivesBlocked = $true
            Write-Log 'Some hives would not unload. Restart the device and run again. Migrate will not start until then.'
        }
    } else {
        Write-Log 'Remediate or Migrate with DryRun false unloads them. A restart also clears them.'
    }
}

# ---------------------------------------------------------------- remediate
$pending = New-Object -TypeName System.Collections.ArrayList
if ($apply) {
    foreach ($r in $rows) {
        if ($r.St.Plan -eq 'Cleanup') {
            $res = Invoke-StrayCleanup -Row $r
            if ($res.Ok) {
                $r.Result = 'Cleaned'
                Update-Data
                $r.St = Get-SubjectState -S $r.S
                Write-Log ('{0}: cleanup done. State is now {1}.' -f $r.S.Name, $r.St.State)
            } else {
                $r.Result = 'Failed'
            }
            Write-Log ('{0}: {1}' -f $r.S.Name, $res.Detail)
        }
        if ($r.St.Plan -eq 'ClearMarker' -and $r.Result -ne 'Failed') {
            $res = Invoke-MarkerClear -Row $r
            if ($res.Ok) {
                if ($r.Result -eq 'Cleaned') { $r.Result = 'Cleaned+MarkerCleared' } else { $r.Result = 'MarkerCleared' }
                Update-Data
                $r.St = Get-SubjectState -S $r.S
                Write-Log ('{0}: marker step done. State is now {1}.' -f $r.S.Name, $r.St.State)
            } else {
                $r.Result = 'Failed'
            }
            Write-Log ('{0}: {1}' -f $r.S.Name, $res.Detail)
        }
        if ($r.St.State -eq 'Ready' -and $r.St.Tidy -and $r.Result -ne 'Failed' -and -not $hivesBlocked) {
            $res = Invoke-ProfileTidy -Row $r
            if ($res.Ok) {
                if ($r.Result -eq 'DryRun') { $r.Result = 'Tidied' } else { $r.Result = '{0}+Tidied' -f $r.Result }
                Update-Data
                $r.St = Get-SubjectState -S $r.S
            } else {
                $r.Result = 'Failed'
            }
            Write-Log ('{0}: {1}' -f $r.S.Name, $res.Detail)
        }
        if ($r.St.Plan -eq 'RepairPerms' -and $r.Result -ne 'Failed') {
            $res = Invoke-PermRepair -Row $r
            if ($res.Ok) { $r.Result = 'Fixed' }
            elseif ($res.Pending) { $r.Result = 'Pending'; [void]$pending.Add($r.S.Name) }
            else { $r.Result = 'Failed' }
            Write-Log ('{0}: {1}' -f $r.S.Name, $res.Detail)
        }
    }
}

# ---------------------------------------------------------------- migrate
if ($modeName -eq 'Migrate') {
    $csvSubjects = @($rows | Where-Object { $_.S.FromCsv })
    $readyRows = @($csvSubjects | Where-Object { $_.St.State -eq 'Ready' })
    if ($hivesBlocked) {
        foreach ($r in $csvSubjects) { $r.Result = 'RestartRequired' }
        Write-Log 'Migrate not started. Leftover hives are still loaded. Restart the device and run again.'
    } elseif ($readyRows.Count -ne $csvSubjects.Count) {
        foreach ($r in $csvSubjects) {
            if ($r.St.State -ne 'Ready') { $r.Result = 'Skipped' }
        }
        Write-Log 'Migrate skipped. Every CSV user for this device must be Ready, because leaving the domain strands the rest.'
    } elseif ($dry) {
        foreach ($r in $readyRows) { $r.Result = 'WouldMigrate' }
        Write-Log ('Dry run. Would migrate: {0}' -f (($readyRows | ForEach-Object { $_.S.Name }) -join ', '))
    } else {
        $problem = $null
        $useSystemContext = [string]::IsNullOrWhiteSpace($JumpCloudAPIKey)
        if (-not (Test-Path -LiteralPath $jcConf)) { $problem = 'JumpCloud agent not found on this device.' }
        elseif ($useSystemContext -and -not (Test-Path -LiteralPath $jcKey)) { $problem = 'No API key given and no system context key on this device.' }
        elseif ($useSystemContext -and @($readyRows | Where-Object { [string]::IsNullOrWhiteSpace($_.S.JcId) }).Count -gt 0) { $problem = 'System context binding needs JumpCloudUserID for every CSV row.' }
        elseif (-not (Get-AdmuExe -Destination $exePath)) { $problem = 'Could not download gui_jcadmu.exe.' }

        if ($problem) {
            Write-Log ('Migrate not started. {0}' -f $problem)
            foreach ($r in $readyRows) { $r.Result = 'Failed'; $r.St.Detail = $problem }
        } else {
            $final = Start-MigrationTask -Rows $readyRows
            foreach ($r in $readyRows) {
                switch ($final.State) {
                    'Succeeded' { $r.Result = 'Migrated' }
                    'Running' { $r.Result = 'Running' }
                    default { $r.Result = $final.State }
                }
                $r.St.Detail = $final.Detail
            }
        }
    }
}

# ---------------------------------------------------------------- pending permission repairs
if ($pending.Count -gt 0 -and $apply) {
    [void](Register-ResumeTask -Users @($pending))
    if ($reboot) {
        Write-Log 'Restart scheduled in 5 minutes.'
        shutdown.exe /r /t 300 /c 'IT maintenance is finishing your account migration. Please save your work.' | Out-Null
    } else {
        Write-Log 'Pending users will be repaired at the next restart by the startup task.'
    }
}
if ($Resume -and $pending.Count -eq 0) {
    Unregister-ScheduledTask -TaskName $taskResume -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log ('Removed startup task {0}.' -f $taskResume)
}

# ---------------------------------------------------------------- summary
Write-Log 'Summary'
$table = @($rows | ForEach-Object {
        [pscustomobject]@{ User = $_.S.Name; State = $_.St.State; Plan = $_.St.Plan; Result = $_.Result; Detail = $_.St.Detail }
    })
$table | Format-Table -AutoSize -Wrap | Out-String -Width 240 | Write-Host

$bad = @($table | Where-Object { $_.State -eq 'NeedsReview' -or $_.Result -in 'Failed', 'Aborted', 'RestartRequired' })
if ($bad.Count -gt 0) { exit 1 }
exit 0
