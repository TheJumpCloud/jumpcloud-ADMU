# Github vars
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

$windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP','Machine')
$workingdir = $windowstemp
$discoverycsvlocation = $workingdir + '\jcdiscovery.csv'

# ADMU vars
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $false
$UpdateHomePath = $false
$AutobindJCUser = $false
$JumpCloudAPIKey = 'yourJCAPIKey'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
# Install Module PowerShellForGitHub
if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
    Install-Module PowerShellForGitHub -Force
}

# Auth to github
Set-GitHubAuthentication -Credential $cred

# Download jcdiscovery.csv from GH
$jcdiscoverycsv = (Get-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Entries | Where-Object {$_.name -match 'jcdiscovery.csv'} | Select-Object name,download_url
    New-Item -ItemType Directory -Force -Path $workingdir | Out-Null
    $dlname = ($workingdir + '\jcdiscovery.csv')
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $wc = New-Object System.Net.Webclient
    $wc.DownloadFile($file.download_url, $dlname)

# Import the CSV & check for one row per system
$ImportedCSV = Import-Csv -Path $discoverycsvlocation
$counts = $ImportedCSV | Group-Object ComputerName
foreach ($i in $counts)
{
    if ($i.count -gt 1)
    {
        write-error "Duplicate system found $($i.Name)"
    }
}

# Find user to be migrated
foreach ($row in $ImportedCSV) {
    if ($row.Computername -eq ($env:COMPUTERNAME)) {
        $SelectedUsername = $row.SID
        $JumpCloudUserName = $row.JumpCloudUserName
    }
}

# Validate parameter are not empty:
If ( -Not ($JumpCloudUserName)::IsNullOrEmpty)
{
    Write-Host "Could not migrate user, entry not found in CSV for JumpCloud Username"
    exit
}

# Install the latest ADMU from PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module JumpCloud.ADMU -Force

# Query User Sessions & logoff
$quserResult = quser
$quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
$quserObject = $quserRegex | ConvertFrom-Csv
If ($quserObject.username){logoff.exe $quserObject.ID}

# Run ADMU
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
Start-Migration -JumpCloudUserName $JumpCloudUserName -SelectedUserName $SelectedUsername -TempPassword $TempPassword -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey