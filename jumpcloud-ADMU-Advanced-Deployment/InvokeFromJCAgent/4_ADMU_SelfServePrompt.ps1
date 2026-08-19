# This script is designed to be run from the JumpCloud Console as a Command. It is invoked by the
# JumpCloud Agent (SYSTEM) on the target system, on a schedule or on demand.

#region config

# Branding (the ONLY place customer branding is set; functions below are brand-agnostic).
$ProductName = 'JumpCloud'
$HelpUrl = 'https://jumpcloud.com/blog/automate-active-directory-migration-tool'
$LogoBase64 = ''                    # optional base64 PNG logo (top-right); '' for none
$HeadingText = ''                   # optional override; default: "<ProductName> Device Migration Required"
$BodyText = ''                      # optional override of the body paragraph(s); '' for default

# Source of the user(s) to migrate on this device. Mirrors 3_ADMU_Invoke.ps1:
#   'CSV'         -> read C:\Windows\Temp\<csvName>, match this device by LocalComputerName + SerialNumber.
#   'Description' -> read the JumpCloud device description (via API), use 'Pending' entries.
$dataSource = 'CSV'
$csvName = 'jcdiscovery.csv'

# JumpCloud API auth (recommended: pass via a secured command variable rather than hardcoding).
$JumpCloudAPIKey = 'YOURAPIKEY'
$JumpCloudOrgID = ''                # required only for multi-tenant / MTP API keys

# Max seconds to wait for the user to make a choice before treating the prompt as closed.
$WaitSeconds = 300

# Migration settings — applied when the user clicks Start. These mirror 3_ADMU_Invoke.ps1 so the
# actual migration behaves identically; only the way it is kicked off (the prompt) is different.
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $true
$UpdateHomePath = $false
$AutoBindJCUser = $true
$BindAsAdmin = $false
$SetDefaultWindowsUser = $true
$systemContextBinding = $false      # bind via the agent (no API key); requires JumpCloudUserID in the source data
$removeMDM = $false
$postMigrationBehavior = 'Restart'  # 'Restart' or 'Shutdown'
$localEXEs = $false                 # use gui_jcadmu.exe staged in C:\Windows\Temp instead of downloading
$SetFullPermission = $false
$BlockAccountLogin = $false          # deny the migrating user from logging back in mid-migration (reverted on completion/failure)
$bypassExeValidation = $false       # TESTING ONLY with $localEXEs: use the staged exe without GitHub validation

# Testing: when $true, Start logs what it WOULD run instead of migrating; Defer logs instead of scheduling.
$DryRun = $false

#endregion config
####
# Do not edit below
####
#region functions
function Get-JcAgentContext {
    # Reads systemKey + region from the local agent config and returns the console URL + API headers.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $false)][string]$OrgID
    )
    $confPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    if (-not (Test-Path -LiteralPath $confPath)) { throw "JumpCloud agent config not found: $confPath" }
    $conf = Get-Content -LiteralPath $confPath -Raw
    $systemKey = [regex]::Match($conf, 'systemKey"?\s*:\s*"?(\w+)').Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($systemKey)) { throw "Could not read systemKey from agent config." }
    $region = [regex]::Match($conf, 'agentServerHost"?\s*:\s*"?agent\.(\w+)\.jumpcloud\.com').Groups[1].Value
    switch ($region) {
        'eu' { $url = 'https://console.eu.jumpcloud.com' }
        'in' { $url = 'https://console.in.jumpcloud.com' }
        default { $url = 'https://console.jumpcloud.com' }
    }
    $headers = @{ 'Accept' = 'application/json'; 'Content-Type' = 'application/json'; 'x-api-key' = $ApiKey }
    if (-not [string]::IsNullOrWhiteSpace($OrgID)) { $headers['x-org-id'] = $OrgID }
    return [PSCustomObject]@{ SystemKey = $systemKey; Url = $url; Headers = $headers }
}

function Get-DeviceMigrationUser {
    # Returns the user(s) to migrate on THIS device, using the same data sources as 3_ADMU_Invoke.ps1.
    # CSV: match rows by LocalComputerName + SerialNumber with a valid JumpCloudUserName + SID.
    # Description: 'Pending' entries with sid + un. This is the authoritative "who to migrate"
    # signal — NOT the console account. Returns @() when there is nothing to migrate.
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $false)][ValidateSet('CSV', 'Description')][string]$Source = 'CSV',
        [Parameter(Mandatory = $false)][string]$CsvName = 'jcdiscovery.csv',
        [Parameter(Mandatory = $false)][string]$Url,
        [Parameter(Mandatory = $false)][hashtable]$Headers,
        [Parameter(Mandatory = $false)][string]$SystemKey
    )
    if ($Source -eq 'CSV') {
        $csvPath = "C:\Windows\Temp\$CsvName"
        if (-not (Test-Path -LiteralPath $csvPath)) { throw "CSV not found: $csvPath" }
        $rows = @(Import-Csv -LiteralPath $csvPath)
        if ($rows.Count -eq 0) { return @() }
        $required = @('LocalComputerName', 'SerialNumber', 'JumpCloudUserName', 'SID', 'LocalPath')
        $have = $rows[0].PSObject.Properties.Name
        foreach ($h in $required) { if ($h -notin $have) { throw "CSV missing header: $h" } }
        $computer = $env:COMPUTERNAME
        $serial = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
        $match = @($rows | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.JumpCloudUserName) -and
                $_.LocalComputerName -eq $computer -and
                $_.SerialNumber -eq $serial -and
                -not [string]::IsNullOrWhiteSpace($_.SID)
            })
        return @($match | ForEach-Object {
                [PSCustomObject]@{ SID = $_.SID; JumpCloudUserName = $_.JumpCloudUserName; LocalPath = $_.LocalPath; JumpCloudUserID = $_.JumpCloudUserID }
            })
    } else {
        $sys = Invoke-RestMethod -Uri "$Url/api/systems/$SystemKey" -Headers $Headers -Method GET
        if ([string]::IsNullOrWhiteSpace($sys.description)) { return @() }
        $entries = @($sys.description | ConvertFrom-Json)
        return @($entries | Where-Object { $_.st -eq 'Pending' -and $_.sid -and $_.un } | ForEach-Object {
                [PSCustomObject]@{ SID = $_.sid; JumpCloudUserName = $_.un; LocalPath = $_.localPath; JumpCloudUserID = $_.uid }
            })
    }
}

function Test-SidLoggedIn {
    # A loaded hive under HKEY_USERS\<SID> means that user has an interactive session.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory = $true)][string]$Sid)
    return (Test-Path -Path "Registry::HKEY_USERS\$Sid")
}

function Convert-SidToAccount {
    # Translates a SID to DOMAIN\user (or COMPUTER\user); returns $null if it cannot be resolved.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][string]$Sid)
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $null
    }
}

function New-PromptRunnerScript {
    # Writes the UI-only WPF runner that the interactive task executes in the user's session.
    # The runner takes all branding as parameters and does NO privileged work; it only shows the
    # form and writes the chosen action ('start'|'defer'|'closed') to the result file.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path
    )
    $runner = @'
param(
    [string]$ResultPath,
    [string]$ProductName,
    [string]$HelpUrl,
    [string]$Heading,
    [string]$Body,
    [string]$LogoBase64
)
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Drawing, System.Windows.Forms
function X([string]$t) {
    if ($null -eq $t) { return '' }
    $t.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("`r`n", '&#10;').Replace("`n", '&#10;')
}
if ([string]::IsNullOrWhiteSpace($Heading)) { $Heading = "$ProductName Device Migration Required" }
if ([string]::IsNullOrWhiteSpace($Body)) {
    $Body = "Your device must be migrated to our new management environment.`n`nThis process is fully automated and takes roughly 10 minutes. Your device MUST BE PLUGGED IN TO POWER/CHARGER. Please save your work before initiating.`n`nClick 'Start Migration' to begin, or 'Defer' to be reminded again later."
}
$title = "$ProductName Device Migration"
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="$(X $title)" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" WindowStyle="SingleBorderWindow"
        Background="White" Width="720" Height="420" Topmost="True">
  <Grid Margin="28">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Grid Grid.Row="0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <TextBlock Grid.Column="0" Text="$(X $Heading)" FontSize="24" FontWeight="Bold" Foreground="#22A45A" TextWrapping="Wrap" VerticalAlignment="Center"/>
      <Image Grid.Column="1" Name="img_logo" Width="72" Height="72" VerticalAlignment="Top"/>
    </Grid>
    <TextBlock Grid.Row="1" Text="$(X $Body)" FontSize="15" Foreground="#333333" TextWrapping="Wrap" Margin="0,20,0,0"/>
    <Grid Grid.Row="2" Margin="0,16,0,0">
      <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
      <Button Grid.Column="0" Name="btn_start" Content="Start Migration" Height="44" MinWidth="170" Foreground="White" Background="#22A45A" FontSize="15" FontWeight="SemiBold" BorderThickness="0" Cursor="Hand"/>
      <Button Grid.Column="1" Name="btn_defer" Content="Defer" Height="44" MinWidth="150" Margin="14,0,0,0" Background="#E6E6E6" Foreground="#333333" FontSize="15" BorderThickness="0" Cursor="Hand"/>
      <TextBlock Grid.Column="3" VerticalAlignment="Center"><Hyperlink Name="lnk_help" Foreground="#555555">Need Help?</Hyperlink></TextBlock>
    </Grid>
  </Grid>
</Window>
"@
$reader = New-Object System.Xml.XmlNodeReader $xaml
$form = [Windows.Markup.XamlReader]::Load($reader)
$script:action = 'closed'
$form.FindName('btn_start').Add_Click({ $script:action = 'start'; $form.Close() })
$form.FindName('btn_defer').Add_Click({ $script:action = 'defer'; $form.Close() })
$lnk = $form.FindName('lnk_help')
if ($lnk -and -not [string]::IsNullOrWhiteSpace($HelpUrl)) { $lnk.Add_Click({ try { Start-Process $HelpUrl } catch {} }) }
$imgLogo = $form.FindName('img_logo')
if (-not [string]::IsNullOrWhiteSpace($LogoBase64) -and $imgLogo) {
    try {
        $bytes = [Convert]::FromBase64String($LogoBase64)
        $stream = New-Object System.IO.MemoryStream(, $bytes)
        $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $bmp.BeginInit(); $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad; $bmp.StreamSource = $stream; $bmp.EndInit()
        $imgLogo.Source = $bmp
    } catch {}
}
$form.ShowDialog() | Out-Null
Set-Content -LiteralPath $ResultPath -Value $script:action -Encoding utf8 -Force
'@
    Set-Content -LiteralPath $Path -Value $runner -Encoding utf8 -Force
}

function Show-PromptInUserSession {
    # Launches the branded prompt in the console user's session via a one-time interactive scheduled
    # task and waits (bounded) for the result. Returns 'start' | 'defer' | 'closed' | 'timeout'.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Account,
        [Parameter(Mandatory = $true)][string]$ProductName,
        [Parameter(Mandatory = $false)][string]$HelpUrl,
        [Parameter(Mandatory = $false)][string]$Heading,
        [Parameter(Mandatory = $false)][string]$Body,
        [Parameter(Mandatory = $false)][string]$LogoBase64,
        [Parameter(Mandatory = $false)][int]$WaitSeconds = 300
    )
    $dir = 'C:\Users\Public\JCADMU'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    # Grant the Users group Modify so the user-context runner can write its result file.
    icacls $dir /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
    $resultPath = Join-Path $dir 'result.txt'
    $runnerPath = Join-Path $dir 'prompt-runner.ps1'
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue

    New-PromptRunnerScript -Path $runnerPath

    $taskName = 'ADMU-SelfServe-Show'
    $argLine = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -ResultPath "{1}" -ProductName "{2}" -HelpUrl "{3}" -Heading "{4}" -Body "{5}" -LogoBase64 "{6}"' -f `
        $runnerPath, $resultPath, $ProductName, $HelpUrl, ($Heading -replace '"', "'"), ($Body -replace '"', "'"), $LogoBase64
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(2)
    $prc = New-ScheduledTaskPrincipal -UserId $Account -LogonType Interactive -RunLevel Limited
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds ($WaitSeconds + 60))
    Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trg -Principal $prc -Settings $set -Description "JumpCloud ADMU: show self-service migration prompt in user session (one-time)." -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $resultPath) { break }
        Start-Sleep -Seconds 2
    }
    $action = if (Test-Path -LiteralPath $resultPath) { (Get-Content -LiteralPath $resultPath -Raw).Trim() } else { 'timeout' }
    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[selfserve] Could not remove temporary task '$taskName': $($_.Exception.Message)"
    }
    return $action
}

# --- Migration execution (ported from 3_ADMU_Invoke.ps1 so the migration flow/logging matches) ---

function ConvertTo-ArgumentList {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$InputHashtable)
    $argumentList = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $InputHashtable.GetEnumerator()) {
        if ($null -ne $entry.Value -and (-not ($entry.Value -is [string]) -or $entry.Value -ne '')) {
            $value = $entry.Value
            $formattedValue = if ($value -is [bool]) { '$' + $value.ToString().ToLower() } else { $value }
            $argumentList.Add(("-{0}:{1}" -f $entry.Key, $formattedValue))
        }
    }
    return $argumentList
}

function Get-JcadmuGuiSha256 {
    [CmdletBinding()]
    param([int]$MaxRetries = 3, [int]$RetryDelaySeconds = 5)
    $apiUrl = 'https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases/latest'
    $headers = @{ 'Accept' = 'application/vnd.github.v3+json' }
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $latestRelease = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -ErrorAction Stop
            $targetAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }
            if ($targetAsset -and $targetAsset.digest -match 'sha256:') {
                return [PSCustomObject]@{ TagName = $latestRelease.tag_name; Version = $latestRelease.tag_name.TrimStart('v', 'V'); SHA256 = $targetAsset.digest.Split(':')[1] }
            }
            throw "SHA256 digest not found for 'gui_jcadmu.exe'."
        } catch {
            if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelaySeconds } else { throw "Failed after $MaxRetries attempts: $($_.Exception.Message)" }
        }
    }
}

function Test-ExeSHA {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$filePath, [int]$MaxRetries = 3, [int]$RetryDelaySeconds = 5, [bool]$AllowUnvalidatedOnApiFailure = $false)
    if (-not (Test-Path -Path $filePath)) { throw "File not found: '$filePath'." }
    $localFileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
    try {
        $releaseInfo = Get-JcadmuGuiSha256 -MaxRetries $MaxRetries -RetryDelaySeconds $RetryDelaySeconds
        return [PSCustomObject]@{ IsValid = ($localFileHash -eq $releaseInfo.SHA256.ToLower()); UsedWithoutValidation = $false }
    } catch {
        if ($AllowUnvalidatedOnApiFailure) {
            Write-Host "[status] Could not validate gui_jcadmu.exe against GitHub; using the local file (localEXEs)."
            return [PSCustomObject]@{ IsValid = $true; UsedWithoutValidation = $true }
        }
        throw "Failed to validate GUI executable: $($_.Exception.Message)"
    }
}

function Get-LatestADMUGUIExe {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$destinationPath = 'C:\Windows\Temp', [int]$MaxRetries = 3, [int]$RetryDelaySeconds = 20, [bool]$useLocalEXEs = $false, [bool]$BypassValidation = $false)
    $fullPath = Join-Path -Path $destinationPath -ChildPath 'gui_jcadmu.exe'
    if ($useLocalEXEs) {
        if (-not (Test-Path -Path $fullPath -PathType Leaf)) { throw "localEXEs is enabled but 'gui_jcadmu.exe' was not found at '$fullPath'." }
        if ($BypassValidation) { Write-Host "[status] Using local gui_jcadmu.exe as-is (bypassExeValidation)."; return $fullPath }
        if ((Test-ExeSHA -filePath $fullPath -AllowUnvalidatedOnApiFailure $true).IsValid) { Write-Host '[status] Local gui_jcadmu.exe validated; skipping download.'; return $fullPath }
        Write-Host '[status] Local gui_jcadmu.exe is not the latest release; downloading.'
    }
    $apiUrl = 'https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases/latest'
    $headers = @{ 'Accept' = 'application/vnd.github.v3+json' }
    $attempt = 0; $success = $false
    while ($attempt -lt $MaxRetries -and -not $success) {
        $attempt++
        try {
            $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
            $exeAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }
            if (-not $exeAsset) { throw "Asset 'gui_jcadmu.exe' not found in release." }
            $fullPath = Join-Path -Path $destinationPath -ChildPath $exeAsset.name
            Write-Host "[status] Downloading gui_jcadmu.exe ($($latestRelease.tag_name))..."
            Invoke-WebRequest -Uri $exeAsset.browser_download_url -OutFile $fullPath -ErrorAction Stop
            $success = $true
        } catch {
            if ($attempt -lt $MaxRetries) { Start-Sleep -Seconds $RetryDelaySeconds } else { throw "Failed to retrieve gui_jcadmu.exe after $MaxRetries attempts: $($_.Exception.Message)" }
        }
    }
    if (-not (Test-Path -Path $fullPath -PathType Leaf)) { throw "Unable to retrieve gui_jcadmu.exe." }
    return $fullPath
}

function Get-DomainStatus {
    [CmdletBinding()]
    param()
    try {
        $ADStatus = dsregcmd.exe /status
        $AzureADStatus = 'Unknown'; $LocalDomainStatus = 'Unknown'
        foreach ($line in $ADStatus) {
            if ($line -match 'AzureADJoined : ') { $AzureADStatus = ($line.TrimStart('AzureADJoined : ')) }
            if ($line -match 'DomainJoined : ') { $LocalDomainStatus = ($line.TrimStart('DomainJoined : ')) }
        }
        return [PSCustomObject]@{ AzureAD = $AzureADStatus; LocalDomain = $LocalDomainStatus }
    } catch {
        return [PSCustomObject]@{ AzureAD = 'Error'; LocalDomain = 'Error' }
    }
}

function Disconnect-UserSession {
    # Log off all interactive sessions so the migrating profile is not loaded (same as 3_ADMU_Invoke.ps1).
    [CmdletBinding()]
    param()
    try {
        $loggedInUsers = (quser) -replace '^>', ' ' | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
        $processedUsers = @()
        foreach ($obj in $loggedInUsers) {
            $processedUsers += if ($obj.Split(',').Count -ne 6) { $obj -replace '(^[^,]+)', '$1,' } else { $obj }
        }
        $usersList = $processedUsers | ConvertFrom-Csv
        foreach ($u in $usersList) {
            if ($u.username) {
                Write-Host "[status] Logging off: $($u.username) (ID: $($u.ID))"
                logoff.exe $($u.ID)
            }
        }
    } catch {
        Write-Host "[status] Could not enumerate/log off sessions: $($_.Exception.Message)"
    }
}

function Start-SelfServeMigration {
    # Runs the migration for a single target user, mirroring 3_ADMU_Invoke.ps1: log off sessions,
    # download/validate gui_jcadmu.exe, run it with the standard Start-Migration parameters, then
    # restart/shutdown. The exe logs to C:\Windows\Temp\jcAdmu.log, exactly like the invoke flow.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][PSCustomObject]$Target,
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][string]$ApiKey,
        [Parameter(Mandatory = $false)][string]$OrgID
    )
    if ($Config.DryRun) {
        Write-Host "[selfserve] (DryRun) would migrate '$($Target.JumpCloudUserName)' (SID $($Target.SID)) then $($Config.postMigrationBehavior)."
        return $true
    }

    $domainStatus = Get-DomainStatus
    Write-Host "[status] Domain status - AzureAD: $($domainStatus.AzureAD), LocalDomain: $($domainStatus.LocalDomain)"

    Write-Host '[status] Acquiring gui_jcadmu.exe...'
    $guiPath = Get-LatestADMUGUIExe -useLocalEXEs $Config.localEXEs -BypassValidation $Config.bypassExeValidation

    Write-Host '[status] Logging off active sessions before migration...'
    Disconnect-UserSession

    $migrationParams = @{
        JumpCloudUserName     = $Target.JumpCloudUserName
        SelectedUserName      = $Target.SID
        TempPassword          = $Config.TempPassword
        UpdateHomePath        = $Config.UpdateHomePath
        AutoBindJCUser        = $Config.AutoBindJCUser
        JumpCloudAPIKey       = $ApiKey
        BindAsAdmin           = $Config.BindAsAdmin
        SetDefaultWindowsUser = $Config.SetDefaultWindowsUser
        LeaveDomain           = $Config.LeaveDomain
        RemoveMDM             = $Config.removeMDM
        adminDebug            = $true
        BlockAccountLogin     = $Config.BlockAccountLogin
    }
    if (-not [string]::IsNullOrWhiteSpace($OrgID)) { $migrationParams['JumpCloudOrgID'] = $OrgID }
    if ($Config.localEXEs) { $migrationParams['localEXEs'] = $true }
    if ($Config.SetFullPermission) { $migrationParams['SetFullPermission'] = $true }
    if ($Config.bypassExeValidation) { $migrationParams['bypassExeValidation'] = $true }
    if ($Config.systemContextBinding) {
        $migrationParams.Remove('AutoBindJCUser'); $migrationParams.Remove('JumpCloudAPIKey'); $migrationParams.Remove('JumpCloudOrgID')
        $migrationParams['systemContextBinding'] = $true
        $migrationParams['JumpCloudUserID'] = $Target.JumpCloudUserID
    }

    if (-not (Test-Path -Path $guiPath)) { Write-Host "[selfserve] gui_jcadmu.exe not found at '$guiPath'."; return $false }
    $convertedParams = ConvertTo-ArgumentList -InputHashtable $migrationParams
    Write-Host "[status] Begin migration for: $($Target.JumpCloudUserName)"
    $out = & $guiPath $convertedParams
    $exitCode = $LASTEXITCODE
    $out | Out-Host
    Write-Host "[status] Migration completed with exit code: $exitCode"

    if ($exitCode -eq 0) {
        Write-Host "[status] Migration successful: $($Target.JumpCloudUserName)"
        if ($Config.ForceReboot) {
            Start-Sleep -Seconds 20
            switch ($Config.postMigrationBehavior) {
                'Shutdown' { Write-Host '[status] Shutting down...'; Stop-Computer -ComputerName localhost -Force }
                default { Write-Host '[status] Restarting...'; Restart-Computer -ComputerName localhost -Force }
            }
        }
        return $true
    } else {
        Write-Host "[status] Migration FAILED: $($Target.JumpCloudUserName)"
        return $false
    }
}

$script:DeferTaskName = 'ADMU-SelfServe-Defer'

function New-DeferLogonTask {
    # Re-shows the prompt at next logon without a JumpCloud command trigger: stage a copy of this
    # script and register an AtLogon task (SYSTEM, no -User filter) that re-runs it locally. Works
    # for any account type (AzureAD/AD/local); the script self-gates on the migrating user.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $false)][bool]$DryRun = $false
    )
    try {
        $dir = 'C:\Windows\JCADMU'   # SYSTEM-only directory (the staged copy contains the API key)
        $localScript = Join-Path $dir 'selfserve.ps1'
        if ($DryRun) {
            Write-Host "[selfserve] (DryRun) would stage '$localScript' and register AtLogon task '$script:DeferTaskName'."
            return $true
        }
        if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
            Write-Host "[selfserve] Cannot stage the logon reminder: script path '$ScriptPath' was not found."
            return $false
        }
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # Copy this script to the staged location (skip when already running from there).
        $srcFull = (Resolve-Path -LiteralPath $ScriptPath).Path
        $dstFull = if (Test-Path -LiteralPath $localScript) { (Resolve-Path -LiteralPath $localScript).Path } else { $localScript }
        if ($srcFull -ne $dstFull) { Copy-Item -LiteralPath $ScriptPath -Destination $localScript -Force }

        $argLine = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$localScript`""
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argLine
        $trg = New-ScheduledTaskTrigger -AtLogOn
        $prc = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest
        $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
        Register-ScheduledTask -TaskName $script:DeferTaskName -Action $act -Trigger $trg -Principal $prc -Settings $set -Description "JumpCloud ADMU: re-show the self-service migration prompt at next logon." -Force | Out-Null
        Write-Host "[selfserve] Registered logon reminder '$script:DeferTaskName'; the prompt will reappear at next logon."
        return $true
    } catch {
        Write-Host "[selfserve] Failed to create logon reminder task: $($_.Exception.Message)"
        return $false
    }
}

function Remove-DeferLogonTask {
    # Cleans up the AtLogon reminder + staged copy (called once there is nothing left to migrate).
    [CmdletBinding()]
    param()
    try {
        Unregister-ScheduledTask -TaskName $script:DeferTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath 'C:\Windows\JCADMU\selfserve.ps1' -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[selfserve] Reminder cleanup issue: $($_.Exception.Message)"
    }
}
#endregion functions

#region main
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Path to this running script, used to stage a local copy for the AtLogon defer reminder. When run
# by the JumpCloud agent this is the agent's temp .ps1; when re-run by the reminder it is the staged copy.
$scriptSelfPath = $PSCommandPath

if ([string]::IsNullOrWhiteSpace($JumpCloudAPIKey) -or $JumpCloudAPIKey -eq 'YOURAPIKEY') {
    Write-Host '[selfserve] JumpCloudAPIKey is required.'
    exit 1
}

try {
    $ctx = Get-JcAgentContext -ApiKey $JumpCloudAPIKey -OrgID $JumpCloudOrgID
} catch {
    Write-Host "[selfserve] $($_.Exception.Message)"
    exit 1
}
Write-Host "[selfserve] systemKey=$($ctx.SystemKey) host=$env:COMPUTERNAME"

# Determine who to migrate on this device from jcdiscovery.csv / description (same as 3_ADMU_Invoke.ps1).
try {
    $targets = Get-DeviceMigrationUser -Source $dataSource -CsvName $csvName -Url $ctx.Url -Headers $ctx.Headers -SystemKey $ctx.SystemKey
} catch {
    Write-Host "[selfserve] Failed to read migration users ($dataSource): $($_.Exception.Message)"
    exit 1
}
if (-not $targets -or @($targets).Count -eq 0) {
    Write-Host "[selfserve] No user to migrate for this device (per $dataSource); nothing to prompt."
    # Nothing left to migrate (e.g. migration already completed) -> remove any lingering reminder.
    Remove-DeferLogonTask
    exit 0
}
Write-Host "[selfserve] Migration user(s) for this device: $((@($targets).JumpCloudUserName) -join ', ')"

# Show the prompt to a target user who is currently logged in (that user's session).
$target = @($targets) | Where-Object { Test-SidLoggedIn -Sid $_.SID } | Select-Object -First 1
if (-not $target) {
    Write-Host '[selfserve] A user to migrate exists but none are logged in; nothing to prompt.'
    exit 0
}
$account = Convert-SidToAccount -Sid $target.SID
if ([string]::IsNullOrWhiteSpace($account)) {
    Write-Host "[selfserve] Could not resolve an account name for SID $($target.SID)."
    exit 1
}
Write-Host "[selfserve] Prompting '$account' (JumpCloud user '$($target.JumpCloudUserName)')."

$action = Show-PromptInUserSession -Account $account -ProductName $ProductName -HelpUrl $HelpUrl -Heading $HeadingText -Body $BodyText -LogoBase64 $LogoBase64 -WaitSeconds $WaitSeconds
Write-Host "[selfserve] User action: $action"

switch ($action) {
    'start' {
        # Run the migration inline for this user, exactly like 3_ADMU_Invoke.ps1 (download exe,
        # log off, run Start-Migration, reboot). Logs stream here and to C:\Windows\Temp\jcAdmu.log.
        $migrationConfig = @{
            TempPassword          = $TempPassword
            LeaveDomain           = $LeaveDomain
            ForceReboot           = $ForceReboot
            UpdateHomePath        = $UpdateHomePath
            AutoBindJCUser        = $AutoBindJCUser
            BindAsAdmin           = $BindAsAdmin
            SetDefaultWindowsUser = $SetDefaultWindowsUser
            systemContextBinding  = $systemContextBinding
            removeMDM             = $removeMDM
            postMigrationBehavior = $postMigrationBehavior
            localEXEs             = $localEXEs
            SetFullPermission     = $SetFullPermission
            BlockAccountLogin     = $BlockAccountLogin
            bypassExeValidation   = $bypassExeValidation
            DryRun                = $DryRun
        }
        $ok = Start-SelfServeMigration -Target $target -Config $migrationConfig -ApiKey $JumpCloudAPIKey -OrgID $JumpCloudOrgID
        if ($ok) {
            # Migrated (or rebooting) -> the reminder is no longer needed.
            Remove-DeferLogonTask
            exit 0
        } else {
            # Migration did not complete -> keep a reminder so the user is prompted again to retry.
            Write-Host '[selfserve] Migration did not complete; will re-prompt at next logon.'
            [void](New-DeferLogonTask -ScriptPath $scriptSelfPath -DryRun $DryRun)
            exit 1
        }
    }
    default {
        # 'defer', 'closed', or 'timeout' -> re-show the prompt at the next logon (any account type),
        # by re-running this script locally from an AtLogon task. No JumpCloud command trigger needed.
        [void](New-DeferLogonTask -ScriptPath $scriptSelfPath -DryRun $DryRun)
        exit 0
    }
}
#endregion main
