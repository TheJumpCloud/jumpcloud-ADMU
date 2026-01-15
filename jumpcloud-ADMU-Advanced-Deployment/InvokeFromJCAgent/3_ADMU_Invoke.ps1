# This script is designed to be run from the JumpCloud Console as a command. It
# will be invoked by the JumpCloud Agent on the target system.
# The script will run the ADMU command to migrate a user to JumpCloud
####
# Update Variables Below
####
#region variables

# Data source for migration users: "CSV"
$dataSource = 'CSV'

# CSV variables - only required if dataSource is set to 'CSV'
# This is the name of the CSV uploaded to the JumpCloud command
$csvName = 'jcdiscovery.csv'

# ADMU variables
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $true
$UpdateHomePath = $false
$AutoBindJCUser = $true
$PrimaryUser = $false
$BindAsAdmin = $false # Bind user as admin (default False)
$JumpCloudAPIKey = 'YOURAPIKEY' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false
$JumpCloudOrgID = 'YOURORGID' # This field is required if you use a MTP API Key
$SetDefaultWindowsUser = $true # Set the default last logged on windows user to the JumpCloud user (default True)
$ReportStatus = $false # Report status back to JumpCloud Description (default False)

# Option to shutdown or restart
# Restarting the system is the default behavior
# If you want to shutdown the system, set the postMigrationBehavior to Shutdown
# The 'shutdown' behavior performs a shutdown of the system in a much faster manner than 'restart' which can take 5 mins form the time the command is issued
$postMigrationBehavior = 'Restart' # Restart or Shutdown

# Option to remove the existing MDM
$removeMDM = $false # Remove the existing MDM (default false)

# option to bind using the systemContext API
$systemContextBinding = $false # Bind using the systemContext API (default False)
# If you want to bind using the systemContext API, set the systemContextBinding to true
# The systemContextBinding option is only available for devices that have enrolled a device using a JumpCloud Administrators Connect Key
# for more information, see the JumpCloud documentation: https://docs.jumpcloud.com/api/2.0/index.html#section/System-Context
#endregion variables
####
# Do not edit below
####
#region functionDefinitions
function Confirm-MigrationParameter {
    [CmdletBinding()]
    param(
        [ValidateSet('CSV', 'Description')][string]$dataSource = 'Description',
        [string]$csvName = 'jcdiscovery.csv',
        [string]$TempPassword = 'Temp123!Temp123!',
        [bool]$LeaveDomain = $true,
        [bool]$ForceReboot = $true,
        [bool]$UpdateHomePath = $false,
        [bool]$AutoBindJCUser = $true,
        [bool]$PrimaryUser = $false,
        [bool]$BindAsAdmin = $false,
        [bool]$SetDefaultWindowsUser = $true,
        [bool]$removeMDM = $true,
        [bool]$systemContextBinding = $false,
        [string]$JumpCloudAPIKey = 'YOURAPIKEY',
        [string]$JumpCloudOrgID = 'YOURORGID',
        [bool]$ReportStatus = $false,
        [ValidateSet('Restart', 'Shutdown')][string]$postMigrationBehavior = 'Restart'
    )
    if ($dataSource -eq 'CSV' -and [string]::IsNullOrWhiteSpace($csvName)) {
        throw "csvName required when dataSource is 'CSV'."
    }
    if ([string]::IsNullOrEmpty($TempPassword)) { throw "TempPassword cannot be empty." }
    if (-not $systemContextBinding) {
        if ([string]::IsNullOrWhiteSpace($JumpCloudAPIKey) -or $JumpCloudAPIKey -eq 'YOURAPIKEY') {
            throw "JumpCloudAPIKey required when systemContextBinding is false."
        }
        if ([string]::IsNullOrWhiteSpace($JumpCloudOrgID) -or $JumpCloudOrgID -eq 'YOURORGID') {
            throw "JumpCloudOrgID required when systemContextBinding is false."
        }
    }
    return $true
}
function Get-MigrationUser {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CSV', 'Description')]
        [string]$source,
        [Parameter(Mandatory = $false)]
        [string]$csvName = 'jcdiscovery.csv',
        [Parameter(Mandatory = $true)]
        [boolean]$systemContextBinding
    )
    if ($source -eq 'CSV') {
        return Get-MgUserFromCSV -csvName $csvName -systemContextBinding $systemContextBinding
    } elseif ($source -eq 'Description') {
        return Get-MgUserFromDesc -systemContextBinding $systemContextBinding
    }
}

function Get-MgUserFromCSV {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$csvName,
        [Parameter(Mandatory = $true)]
        [boolean]$systemContextBinding
    )
    begin {
        $csvPath = "C:\Windows\Temp\$csvName"
        if (-not (Test-Path -Path $csvPath -PathType Leaf)) {
            throw "CSV file not found: '$csvPath'."
        }
        $ImportedCSV = Import-Csv -Path $csvPath -ErrorAction Stop
    }
    process {
        $requiredHeaders = @("LocalComputerName", "SerialNumber", "JumpCloudUserName", "SID", "LocalPath")
        $csvHeaders = $ImportedCSV[0].PSObject.Properties.Name
        foreach ($header in $requiredHeaders) {
            if ($header -notin $csvHeaders) { throw "CSV missing header: '$header'." }
        }
        $usersToMigrate = New-Object System.Collections.ArrayList
        $computerName = hostname
        if ([string]::IsNullOrWhiteSpace($computerName)) { $computerName = $env:COMPUTERNAME }
        try {
            $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
        } catch {
            $serialNumber = (Get-CimInstance -Class Win32_BIOS).SerialNumber
        }
        $ValidDeviceRows = $ImportedCSV | Where-Object {
            ((-not [string]::IsNullOrWhiteSpace($_.JumpCloudUserName))) -and
            ($_.LocalComputerName -eq $computerName) -and ($_.SerialNumber -eq $serialNumber)
        }
        $duplicateSids = $ValidDeviceRows | Group-Object -Property 'SID' | Where-Object { $_.Count -gt 1 }
        if ($duplicateSids) { throw "Duplicate SID found: '$($duplicateSids[0].Name)'." }
        foreach ($row in $ValidDeviceRows) {
            if ($systemContextBinding -and [string]::IsNullOrWhiteSpace($row.JumpCloudUserID)) {
                throw "JumpCloudUserID required for systemContextBinding."
            }
            $requiredFields = "LocalPath", "SID"
            foreach ($field in $requiredFields) {
                if ([string]::IsNullOrWhiteSpace($row.$field)) {
                    throw "Field '$field' empty for user '$($row.JumpCloudUserName)'."
                }
            }
            $usersToMigrate.Add([PSCustomObject]@{
                    SelectedUsername  = $row.SID
                    LocalPath         = $row.LocalPath
                    JumpCloudUserName = $row.JumpCloudUserName
                    JumpCloudUserID   = $row.JumpCloudUserID
                }) | Out-Null
        }
    }
    end {
        if ($usersToMigrate.Count -eq 0) { throw "No users found in CSV matching this computer." }
        return $usersToMigrate
    }
}

function Get-MgUserFromDesc {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param([Parameter(Mandatory = $true)][boolean]$systemContextBinding)
    process {
        try {
            Write-Host "[status] Retrieving system description..."
            $systemDescription = Get-SystemDescription -systemContextBinding $systemContextBinding
        } catch {
            throw "Failed to retrieve system description: $_"
        }
        if ([string]::IsNullOrEmpty($systemDescription)) { Write-Host "[status] System description is empty."; return $null }
        try { $users = $systemDescription | ConvertFrom-Json } catch { throw "Invalid JSON: $_" }
        if ($users.GetType().Name -eq 'PSCustomObject') { $users = @($users) }
        $usersToMigrate = New-Object System.Collections.ArrayList
        foreach ($user in $users) {
            if ([string]::IsNullOrWhiteSpace($user.sid)) { continue }
            if ([string]::IsNullOrWhiteSpace($user.un)) { continue }
            if ($user.st -eq 'Skip') { continue }
            if ($user.st -ne 'Pending') { continue }
            if ($systemContextBinding -and [string]::IsNullOrWhiteSpace($user.uid)) { throw "User '$($user.un)' missing 'uid'." }
            [void]$usersToMigrate.Add([PSCustomObject]@{
                    SelectedUsername  = $user.sid
                    JumpCloudUserName = $user.un
                    LocalPath         = $user.localPath
                    JumpCloudUserID   = $user.uid
                })
            Write-Host "[status] User queued: $($user.un)"
        }
        if ($usersToMigrate.Count -eq 0) { Write-Host "[status] No eligible users found."; return $null }
        return @(, $usersToMigrate)
    }
}
function Get-LatestADMUGUIExe {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $false)][string]$destinationPath = "C:\Windows\Temp",
        [Parameter(Mandatory = $false)][string]$GitHubToken,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)][int]$RetryDelaySeconds = 20
    )
    begin {
        $owner = "TheJumpCloud"
        $repo = "jumpcloud-ADMU"
        $apiUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
        $headers = @{"Accept" = "application/vnd.github.v3+json" }
        if (-not [string]::IsNullOrEmpty($GitHubToken)) {
            $headers["Authorization"] = "Bearer $GitHubToken"
            Write-Host "Using authenticated GitHub API" -ForegroundColor Cyan
        }
    }
    process {
        $attempt = 0
        $success = $false
        while ($attempt -lt $MaxRetries -and -not $success) {
            $attempt++
            try {
                if ($attempt -gt 1) { Write-Host "Retry attempt $attempt of $MaxRetries..." -ForegroundColor Yellow }
                Write-Host "Querying GitHub for latest release..." -ForegroundColor Yellow
                $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
                $exeAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }
                if ($exeAsset) {
                    $downloadUrl = $exeAsset.browser_download_url
                    $fileName = $exeAsset.name
                    $fullPath = Join-Path -Path $destinationPath -ChildPath $fileName
                    Write-Host "Downloading '$fileName' (Version $($latestRelease.tag_name))..." -ForegroundColor Yellow
                    $dlAttempt = 0
                    while ($dlAttempt -lt $MaxRetries) {
                        $dlAttempt++
                        try {
                            Invoke-WebRequest -Uri $downloadUrl -OutFile $fullPath -ErrorAction Stop
                            Write-Host "Download complete!" -ForegroundColor Green
                            $success = $true
                            break
                        } catch {
                            if ($dlAttempt -lt $MaxRetries) {
                                Write-Host "Download failed. Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                                Start-Sleep -Seconds $RetryDelaySeconds
                            } else {
                                throw "$($_.Exception.Message)"
                            }
                        }
                    }
                } else {
                    throw "Asset 'gui_jcadmu.exe' not found in release."
                }
            } catch {
                $errorMessage = $_.Exception.Message
                if ($errorMessage -match "rate limit|403") {
                    Write-Host "GitHub API rate limit issue." -ForegroundColor Yellow
                    if ([string]::IsNullOrEmpty($GitHubToken)) {
                        Write-Host "Hint: Use -GitHubToken for higher limits." -ForegroundColor Cyan
                    }
                }
                if ($attempt -lt $MaxRetries) {
                    Write-Host "Waiting $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $RetryDelaySeconds
                } else {
                    throw "Failed after $MaxRetries attempts: $errorMessage"
                }
            }
        }
    }
}
function ConvertTo-ArgumentList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable]
        $InputHashtable
    )
    $argumentList = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $InputHashtable.GetEnumerator()) {
        if ($null -ne $entry.Value -and (-not ($entry.Value -is [string]) -or $entry.Value -ne '')) {
            $key = $entry.Key
            $value = $entry.Value
            $formattedValue = if ($value -is [bool]) {
                '$' + $value.ToString().ToLower()
            } else {
                $value
            }
            $argument = "-{0}:{1}" -f $key, $formattedValue
            $argumentList.Add($argument)
        }
    }
    return $argumentList
}
function Get-JcadmuGuiSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$GitHubToken,
        [Parameter(Mandatory = $false)][int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)][int]$RetryDelaySeconds = 5
    )
    begin {
        $apiUrl = "https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases"
        $headers = @{"Accept" = "application/vnd.github.v3+json" }
        if (-not [string]::IsNullOrEmpty($GitHubToken)) {
            $headers["Authorization"] = "Bearer $GitHubToken"
        }
    }
    process {
        $attempt = 0
        while ($attempt -lt $MaxRetries) {
            $attempt++
            try {
                if ($attempt -gt 1) { Write-Host "Retry attempt $attempt..." -ForegroundColor Yellow }
                $releases = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -ErrorAction Stop
                if ($null -eq $releases -or $releases.Count -eq 0) { throw "No releases found." }
                $latestRelease = $releases[0]
                $targetAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }
                if ($targetAsset -and $targetAsset.digest -match "sha256:") {
                    $sha256 = $targetAsset.digest.Split(':')[1]
                    return [PSCustomObject]@{ TagName = $latestRelease.tag_name; SHA256 = $sha256 }
                } else {
                    throw "SHA256 digest not found for 'gui_jcadmu.exe'."
                }
            } catch {
                if ($_.Exception.Message -match "rate limit|403") {
                    Write-Host "GitHub API rate limit issue." -ForegroundColor Yellow
                }
                if ($attempt -lt $MaxRetries) {
                    Write-Host "Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $RetryDelaySeconds
                } else {
                    throw "Failed after $MaxRetries attempts: $($_.Exception.Message)"
                }
            }
        }
    }
}
function Test-ExeSHA {
    param (
        [Parameter(Mandatory = $true)][string]$filePath,
        [Parameter(Mandatory = $false)][string]$GitHubToken
    )
    process {
        if (-not (Test-Path -Path $filePath)) { throw "File not found: '$filePath'." }
        $releaseSHA256 = if ($GitHubToken) { (Get-JcadmuGuiSha256 -GitHubToken $GitHubToken).SHA256 } else { (Get-JcadmuGuiSha256).SHA256 }
        $localFileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
        Write-Host "[status] Official SHA256: $releaseSHA256"
        Write-Host "[status] Local SHA256:    $localFileHash"
        if ($localFileHash -eq $releaseSHA256.ToLower()) {
            Write-Host "[status] SUCCESS: Hash validation passed!"
        } else {
            throw "[status] Hash mismatch! File differs from official release."
        }
    }
}
function Invoke-UserMigrationBatch {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][array]$UsersToMigrate,
        [Parameter(Mandatory = $true)][hashtable]$MigrationConfig
    )
    $results = [PSCustomObject]@{
        TotalUsers           = $UsersToMigrate.Count
        SuccessfulMigrations = 0
        FailedMigrations     = 0
        MigrationDetails     = @()
        SuccessfulUsers      = @()
        FailedUsers          = @()
        StartTime            = Get-Date
        EndTime              = $null
        Duration             = $null
    }
    $lastUser = $UsersToMigrate | Select-Object -Last 1
    foreach ($user in $UsersToMigrate) {
        $userStartTime = Get-Date
        $isLastUser = ($user -eq $lastUser)
        $leaveDomainParam = if ($isLastUser -and $MigrationConfig.LeaveDomainAfterMigration) { $true } else { $false }
        $removeMDMParam = if ($isLastUser -and $MigrationConfig.RemoveMDM) { $true } else { $false }
        $migrationParams = @{
            JumpCloudUserName     = $user.JumpCloudUserName
            SelectedUserName      = $user.selectedUsername
            TempPassword          = $MigrationConfig.TempPassword
            UpdateHomePath        = $MigrationConfig.UpdateHomePath
            AutoBindJCUser        = $MigrationConfig.AutoBindJCUser
            PrimaryUser           = $MigrationConfig.PrimaryUser
            JumpCloudAPIKey       = $MigrationConfig.JumpCloudAPIKey
            BindAsAdmin           = $MigrationConfig.BindAsAdmin
            SetDefaultWindowsUser = $MigrationConfig.SetDefaultWindowsUser
            LeaveDomain           = $leaveDomainParam
            RemoveMDM             = $removeMDMParam
            adminDebug            = $true
            ReportStatus          = $MigrationConfig.ReportStatus
        }
        if (-not [string]::IsNullOrEmpty($MigrationConfig.JumpCloudOrgID)) {
            $migrationParams.Add('JumpCloudOrgID', $MigrationConfig.JumpCloudOrgID)
        }
        if ($MigrationConfig.systemContextBinding -eq $true) {
            $migrationParams.Remove('AutoBindJCUser')
            $migrationParams.Remove('JumpCloudAPIKey')
            $migrationParams.Remove('JumpCloudOrgID')
            $migrationParams.Add('systemContextBinding', $true)
            $migrationParams.Add('JumpCloudUserID', $user.JumpCloudUserID)
        }
        $domainStatus = Get-DomainStatus
        Write-Host "[status] Domain status - Azure/EntraID: $($domainStatus.AzureAD), Local Domain: $($domainStatus.LocalDomain)"
        Write-Host "[status] Begin migration for: $($user.JumpCloudUserName)"
        $migrationResult = Invoke-SingleUserMigration -User $user -MigrationParams $migrationParams -GuiJcadmuPath $MigrationConfig.guiJcadmuPath
        $userResult = [PSCustomObject]@{
            JumpCloudUserName  = $user.JumpCloudUserName
            SelectedUsername   = $user.selectedUsername
            Success            = $migrationResult.Success
            ErrorMessage       = $migrationResult.ErrorMessage
            DomainStatusBefore = $domainStatus
            StartTime          = $userStartTime
            EndTime            = Get-Date
            Duration           = (Get-Date) - $userStartTime
            IsLastUser         = $isLastUser
            LeaveDomain        = $leaveDomainParam
        }
        $results.MigrationDetails += $userResult
        if ($migrationResult.Success) {
            $results.SuccessfulMigrations++
            $results.SuccessfulUsers += $userResult
            Write-Host "[status] Migration successful: $($user.JumpCloudUserName)"
        } else {
            $results.FailedMigrations++
            $results.FailedUsers += $userResult
            Write-Host "[status] Migration failed: $($user.JumpCloudUserName)"
        }
    }
    $results.EndTime = Get-Date
    $results.Duration = $results.EndTime - $results.StartTime
    return $results
}
function Invoke-SingleUserMigration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][PSCustomObject]$User,
        [Parameter(Mandatory = $true)][hashtable]$MigrationParams,
        [Parameter(Mandatory = $true)][string]$GuiJcadmuPath
    )
    if (-not (Test-Path -Path $GuiJcadmuPath)) { throw "File not found: '$GuiJcadmuPath'." }
    $convertedParams = ConvertTo-ArgumentList -InputHashtable $MigrationParams
    Write-Host "[status] Executing migration command..."
    $result = & $GuiJcadmuPath $convertedParams
    $exitCode = $LASTEXITCODE
    Write-Host "[status] Migration completed with exit code: $exitCode"
    Write-Host "`n[status] Migration output:"
    $result | Out-Host
    return [PSCustomObject]@{
        Success      = ($exitCode -eq 0)
        ErrorMessage = if ($exitCode -ne 0) { $result[-1] } else { $null }
    }
}
function Get-DomainStatus {
    [CmdletBinding()]
    param()
    try {
        $ADStatus = dsregcmd.exe /status
        $AzureADStatus = "Unknown"
        $LocalDomainStatus = "Unknown"
        foreach ($line in $ADStatus) {
            if ($line -match "AzureADJoined : ") { $AzureADStatus = ($line.TrimStart('AzureADJoined : ')) }
            if ($line -match "DomainJoined : ") { $LocalDomainStatus = ($line.TrimStart('DomainJoined : ')) }
        }
        return [PSCustomObject]@{ AzureAD = $AzureADStatus; LocalDomain = $LocalDomainStatus }
    } catch {
        Write-Host "[status] Error getting domain status: $($_.Exception.Message)"
        return [PSCustomObject]@{ AzureAD = "Error"; LocalDomain = "Error" }
    }
}
function Get-SystemDescription {
    param([bool]$systemContextBinding)
    if (-not $systemContextBinding) { throw "Description source requires systemContextBinding=`$true" }
    try {
        $cfg = Get-Content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $key = [regex]::Match($cfg, 'systemKey["]?:["]?(\w+)').Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($key)) { throw "No systemKey" }
        $host_match = [regex]::Match($cfg, 'agentServerHost["]?:["]?agent\.(\w+)\.jumpcloud\.com').Groups[1].Value
        $url = if ($host_match -eq "eu") { "https://console.jumpcloud.eu" }else { "https://console.jumpcloud.com" }
        $privKey = 'C:\Program Files\JumpCloud\Plugins\Contrib\client.key'
        if (-not(Test-Path $privKey)) { throw "Key not found" }
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            if (-not([System.Management.Automation.PSTypeName]'RSAEncryption.RSAEncryptionProvider').Type) {
                $rsaType = @'
using System;using System.Collections.Generic;using System.IO;using System.Net;using System.Runtime.InteropServices;using System.Security;using System.Security.Cryptography;using System.Text;namespace RSAEncryption{public class RSAEncryptionProvider{public static RSACryptoServiceProvider GetRSAProviderFromPemFile(String pemfile,SecureString p=null){const String h="-----BEGIN PUBLIC KEY-----";const String f="-----END PUBLIC KEY-----";bool isPrivate=true;byte[]pk=null;if(!File.Exists(pemfile)){throw new Exception("key not found");}string ps=File.ReadAllText(pemfile).Trim();if(ps.StartsWith(h)&&ps.EndsWith(f)){isPrivate=false;}if(isPrivate){pk=ConvertPrivateKeyToBytes(ps,p);if(pk==null){return null;}return DecodeRSAPrivateKey(pk);}return null;}static byte[]ConvertPrivateKeyToBytes(String i,SecureString p=null){const String ph="-----BEGIN RSA PRIVATE KEY-----";const String pf="-----END RSA PRIVATE KEY-----";String ps=i.Trim();byte[]bk;if(!ps.StartsWith(ph)||!ps.EndsWith(pf)){return null;}StringBuilder sb=new StringBuilder(ps);sb.Replace(ph,"");sb.Replace(pf,"");String pvs=sb.ToString().Trim();try{bk=Convert.FromBase64String(pvs);return bk;}catch(System.FormatException){StringReader sr=new StringReader(pvs);if(!sr.ReadLine().StartsWith("Proc-Type"))return null;String sl=sr.ReadLine();if(!sl.StartsWith("DEK-Info"))return null;String ss=sl.Substring(sl.IndexOf(",")+1).Trim();byte[]salt=new byte[ss.Length/2];for(int idx=0;idx<salt.Length;idx++)salt[idx]=Convert.ToByte(ss.Substring(idx*2,2),16);if(!(sr.ReadLine()==""))return null;String es="";String l="";while((l=sr.ReadLine())!=null){es+=l;}bk=Convert.FromBase64String(es);byte[]dk=GetEncryptedKey(salt,p,1,1);byte[]iv=new byte[8];Array.Copy(salt,0,iv,0,8);bk=DecryptKey(bk,dk,iv);return bk;}}public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[]pk){byte[]M,E,D,P,Q,DP,DQ,IQ;MemoryStream m=new MemoryStream(pk);BinaryReader br=new BinaryReader(m);byte b=0;ushort t=0;int e=0;try{t=br.ReadUInt16();if(t==0x8130)br.ReadByte();else if(t==0x8230)br.ReadInt16();else return null;t=br.ReadUInt16();if(t!=0x0102)return null;b=br.ReadByte();if(b!=0x00)return null;e=GetIntegerSize(br);M=br.ReadBytes(e);e=GetIntegerSize(br);E=br.ReadBytes(e);e=GetIntegerSize(br);D=br.ReadBytes(e);e=GetIntegerSize(br);P=br.ReadBytes(e);e=GetIntegerSize(br);Q=br.ReadBytes(e);e=GetIntegerSize(br);DP=br.ReadBytes(e);e=GetIntegerSize(br);DQ=br.ReadBytes(e);e=GetIntegerSize(br);IQ=br.ReadBytes(e);RSACryptoServiceProvider RSA=new RSACryptoServiceProvider();RSAParameters RP=new RSAParameters();RP.Modulus=M;RP.Exponent=E;RP.D=D;RP.P=P;RP.Q=Q;RP.DP=DP;RP.DQ=DQ;RP.InverseQ=IQ;RSA.ImportParameters(RP);return RSA;}catch(Exception){return null;}finally{br.Close();}}private static int GetIntegerSize(BinaryReader br){byte b=0;byte lb=0x00;byte hb=0x00;int c=0;b=br.ReadByte();if(b!=0x02)return 0;b=br.ReadByte();if(b==0x81)c=br.ReadByte();else if(b==0x82){hb=br.ReadByte();lb=br.ReadByte();byte[]mi={lb,hb,0x00,0x00};c=BitConverter.ToInt32(mi,0);}else{c=b;}while(br.ReadByte()==0x00){c--;}br.BaseStream.Seek(-1,SeekOrigin.Current);return c;}static byte[]GetEncryptedKey(byte[]salt,SecureString sp,int c,int m){IntPtr up=IntPtr.Zero;int HL=16;byte[]km=new byte[HL*m];byte[]pb=new byte[sp.Length];up=Marshal.SecureStringToGlobalAllocAnsi(sp);Marshal.Copy(up,pb,0,pb.Length);Marshal.ZeroFreeGlobalAllocAnsi(up);byte[]d00=new byte[pb.Length+salt.Length];Array.Copy(pb,d00,pb.Length);Array.Copy(salt,0,d00,pb.Length,salt.Length);MD5 md=new MD5CryptoServiceProvider();byte[]res=null;byte[]ht=new byte[HL+d00.Length];for(int j=0;j<m;j++){res=md.ComputeHash(ht);Array.Copy(res,0,ht,0,res.Length);Array.Copy(d00,0,ht,res.Length,d00.Length);}byte[]dk=new byte[24];Array.Copy(km,dk,dk.Length);Array.Clear(pb,0,pb.Length);Array.Clear(d00,0,d00.Length);Array.Clear(res,0,res.Length);Array.Clear(ht,0,ht.Length);Array.Clear(km,0,km.Length);return dk;}static byte[]DecryptKey(byte[]cd,byte[]dek,byte[]iv){MemoryStream ms=new MemoryStream();TripleDES alg=TripleDES.Create();alg.Key=dek;alg.IV=iv;try{CryptoStream cs=new CryptoStream(ms,alg.CreateDecryptor(),CryptoStreamMode.Write);cs.Write(cd,0,cd.Length);cs.Close();}catch(Exception){return null;}byte[]dd=ms.ToArray();return dd;}}}
'@
                Add-Type -TypeDefinition $rsaType
            }
            $rsa = [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($privKey)
        } else {
            $pem = Get-Content -Path $privKey -Raw
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $rsa.ImportFromPem($pem)
        }
        $now = (Get-Date -Date ((Get-Date).ToUniversalTime())-UFormat '+%a, %d %h %Y %H:%M:%S GMT')
        $signstr = "GET /api/systems/$key HTTP/1.1`ndate: $now"
        $enc = [system.Text.Encoding]::UTF8
        $data = $enc.GetBytes($signstr)
        $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        $hr = $sha.ComputeHash($data)
        $ha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        $sb = $rsa.SignHash($hr, $ha, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $sig = [Convert]::ToBase64String($sb)
        $h = @{Accept = "application/json"; Date = "$now"; Authorization = "Signature keyId=`"system/$key`",headers=`"request-line date`",algorithm=`"rsa-sha256`",signature=`"$sig`"" }
        $sys = Invoke-RestMethod -Method GET -Uri "$url/api/systems/$key" -Headers $h
        return $sys.description
    } catch { throw "Failed to get description: $_" }
}
#endregion functionDefinitions
#region validation
$confirmMigrationParameters = Confirm-MigrationParameter -dataSource $dataSource -csvName $csvName -TempPassword $TempPassword -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutoBindJCUser $AutoBindJCUser -PrimaryUser $PrimaryUser -BindAsAdmin $BindAsAdmin -SetDefaultWindowsUser $SetDefaultWindowsUser -systemContextBinding $systemContextBinding -JumpCloudAPIKey $JumpCloudAPIKey -JumpCloudOrgID $JumpCloudOrgID -postMigrationBehavior $postMigrationBehavior -removeMDM $removeMDM -ReportStatus $ReportStatus
if ($confirmMigrationParameters) { Write-Host "[STATUS] Migration parameters validated successfully." }
#endregion validation
#region dataImport
if ($dataSource -eq 'CSV') {
    Write-Host "[status] Using CSV source..."
    if (-not $csvName) { Write-Host "[status] csvName not set, exiting..."; exit 1 }
} elseif ($dataSource -eq 'Description') {
    Write-Host "[status] Using system description source..."
}
try {
    $UsersToMigrate = Get-MigrationUser -source $dataSource -csvName $csvName -systemContextBinding $systemContextBinding
} catch {
    Write-Host "[ERROR] Failed to retrieve migration users: $_"
    exit 1
}
#endregion dataImport
if (-not $UsersToMigrate) { Write-Host "[status] No users to migrate, exiting..."; exit 1 }
#region logoffUsers
$loggedInUsers = (quser) -replace '^>', ' ' | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
$processedUsers = @()
foreach ($obj in $loggedInUsers) {
    $processedUsers += if ($obj.Split(',').Count -ne 6) { $obj -replace '(^[^,]+)', '$1,' } else { $obj }
}
$UsersList = $processedUsers | ConvertFrom-Csv
Write-Host "[status] Logging off users..."
foreach ($user in $UsersList) {
    if ($user.username) {
        Write-Host "[status] Logging off: $($user.username) (ID: $($user.ID))"
        logoff.exe $($user.ID)
    }
}
#endregion logoffUsers
if ($LeaveDomain) {
    $LeaveDomain = $false
    Write-Host "[status] Domain will be un-joined for last user migrated"
    $LeaveDomainAfterMigration = $true
}
if ($ForceReboot) {
    $ForceReboot = $false
    Write-Host "[status] System will $postMigrationBehavior after last user is migrated"
    $ForceRebootAfterMigration = $true
}
#endregion logoffUsers (implied)
#region migration
$guiJcadmuPath = "C:\Windows\Temp\gui_jcadmu.exe"
Get-LatestADMUGUIExe
Test-ExeSHA -filePath $guiJcadmuPath
$migrationResults = Invoke-UserMigrationBatch -UsersToMigrate $UsersToMigrate -MigrationConfig @{
    TempPassword              = $TempPassword
    UpdateHomePath            = $UpdateHomePath
    AutoBindJCUser            = $AutoBindJCUser
    PrimaryUser               = $PrimaryUser
    JumpCloudAPIKey           = $JumpCloudAPIKey
    BindAsAdmin               = $BindAsAdmin
    SetDefaultWindowsUser     = $SetDefaultWindowsUser
    ReportStatus              = $ReportStatus
    JumpCloudOrgID            = $JumpCloudOrgID
    systemContextBinding      = $systemContextBinding
    LeaveDomainAfterMigration = $LeaveDomainAfterMigration
    removeMDM                 = $removeMDM
    guiJcadmuPath             = $guiJcadmuPath
}
Write-Host "`nResults - Total: $($migrationResults.TotalUsers), Success: $($migrationResults.SuccessfulMigrations), Failed: $($migrationResults.FailedMigrations)"
if ($migrationResults.FailedUsers.Count -gt 0) {
    Write-Host "`nFailed Users:"
    foreach ($failedUser in $migrationResults.FailedUsers) { Write-Host "  - $($failedUser.JumpCloudUserName)" }
    exit 1
} else {
    #region restart/shutdown
    if ($ForceRebootAfterMigration) {
        Start-Sleep 20
        switch ($postMigrationBehavior) {
            'shutdown' { Write-Host "[status] Shutting down..."; Stop-Computer -ComputerName localhost -force }
            'restart' { Write-Host "[status] Restarting..."; Restart-Computer -ComputerName localhost -force }
        }
    }
    #endregion restart/shutdown
}
#endregion migration
exit 0