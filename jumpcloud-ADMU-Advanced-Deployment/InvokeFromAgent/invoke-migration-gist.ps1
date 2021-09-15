# These Variables must match your environment
$JcApiKey = 'yourJCAPIKey'
$GHUsername = 'yourGhUsername'
$GHToken = 'yourGhToken'
$GHGistDescription = 'ADMU_RESULT'

# These variables are built automatically
$Hostname = $env:COMPUTERNAME
$DiscoveryCSV = 'C:\Windows\Temp\ADMUDiscovery.csv';
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
# Install Module PowerShellForGitHub
Install-Module PowerShellForGitHub -Force

Set-GitHubAuthentication -Credential $cred

$gist = Get-GitHubGist -UserName $GHUsername | Where-Object { $_.description -eq $GHGistDescription }
Get-GitHubGist -Gist $gist.gistid -Path 'C:\Windows\Temp\'-Force
# Import the CSV
$ImportedCSV = Import-Csv -Path $DiscoveryCSV
# If Duplicates are found exit
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
    if ($row.Computername -eq $Hostname) {
        # If system is domain bound, $SelectedUsername can be "Domain\userToConvert"
        # Else, enter the SID of the user to Convert
        # Get the username of the JumpCloud User from CSV
        $SelectedUsername = $row.SelectedUserName
        $JumpCloudUserName = $row.JumpCloudUserName
        $TempPassword = $row.TempPassword
        $JumpCloudConnectKey = $row.JumpCloudConnectKey
        $AcceptEULA = [System.Convert]::ToBoolean($($row.AcceptEULA))
        $LeaveDomain = [System.Convert]::ToBoolean($($row.LeaveDomain))
        $ConvertProfile = [System.Convert]::ToBoolean($($row.ConvertProfile))
        $AzureADProfile = [System.Convert]::ToBoolean($($row.AzureADProfile))
        $InstallJCAgent = [System.Convert]::ToBoolean($($row.InstallJCAgent))
    }
}

# Validate parameters are not empty:
If ( -Not ($SelectedUsername)::IsNullOrEmpty){
    Write-Host "Could not migrate user, entry not found in CSV for Selected Username"
    exit
}
If ( -Not ($JumpCloudUserName)::IsNullOrEmpty)
{
    Write-Host "Could not migrate user, entry not found in CSV for JumpCloud Username"
    exit
}
If ( -Not ($TempPassword)::IsNullOrEmpty)
{
    Write-Host "Could not migrate user, entry not found in CSV for TempPassword"
    exit
}
Write-Host "Converting ADMU with the following options:"
Write-Host "SelectedUsername = $SelectedUsername"
Write-Host "JumpCloudUserName = $JumpCloudUserName"
Write-Host "TempPassword = $TempPassword"
Write-Host "AcceptEULA = $AcceptEULA"
Write-Host "LeaveDomain = $LeaveDomain"
Write-Host "ConvertProfile = $ConvertProfile"
Write-Host "AzureADProfile = $AzureADProfile"
Write-Host "InstallJCAgent = $InstallJCAgent"


# Install the ADMU
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Install-PackageProvider -Name NuGet -Force
Install-Module JumpCloud.ADMU -Force

# Query User Sessions
$quserResult = quser
$quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
$quserObject = $quserRegex | ConvertFrom-Csv

# If the username of logged in user matches the profile path of the user we want
# to migrate, log them off.
If ($quserObject.username)
{
    # TODO: Logout if match
    logoff.exe $quserObject.ID
}
# Kick off the ADMU with the SID from the selected user.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
Start-Migration -JumpCloudUserName $JumpCloudUserName -SelectedUserName $SelectedUsername -TempPassword $TempPassword -AcceptEULA $AcceptEULA -LeaveDomain $LeaveDomain -ConvertProfile $ConvertProfile -AzureADProfile $AzureADProfile -JumpCloudConnectKey $JumpCloudConnectKey -InstallJCAgent $InstallJCAgent

# Step 2 - Bind User Steps
# Get the JumpCloud SystemKey
$config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
$regex = 'systemKey\":\"(\w+)\"'
$systemKey = [regex]::Match($config, $regex).Groups[1].Value
if ($systemKey){
    $Headers = @{
        'Accept'       = 'application/json';
        'Content-Type' = 'application/json';
        'x-api-key'    = $JcApiKey;
    }
    $Form = @{
        'filter' = "username:eq:$($JumpcloudUserName)"
    }
    Try{
        Write-Host "Getting information from SystemID: $systemKey"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Response = Invoke-WebRequest -Method 'Get' -Uri "https://console.jumpcloud.com/api/systemusers" -Headers $Headers -Body $Form -UseBasicParsing
        $StatusCode = $Response.StatusCode
    }
    catch
    {
        $StatusCode = $_.Exception.Response.StatusCode.value__
    }
    # Get Results, convert from Json
    $Results = $Response.Content | ConvertFrom-JSON
    $JcUserId = $Results.results.id
    # Bind Step
    if ($JcUserId){
        $Headers = @{
            'Accept'    = 'application/json';
            'x-api-key' = $JcApiKey
        }
        $Form = @{
            'op'   = 'add';
            'type' = 'system';
            'id'   = "$systemKey"
        } | ConvertTo-Json
        Try
        {
            Write-Host "Binding $JumpcloudUserName with userId: $JcUserId to SystemID: $systemKey"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $Response = Invoke-WebRequest -Method 'Post' -Uri "https://console.jumpcloud.com/api/v2/users/$JcUserId/associations" -Headers $Headers -Body $Form -ContentType 'application/json' -UseBasicParsing
            $StatusCode = $Response.StatusCode
        }
        catch
        {
            $StatusCode = $_.Exception.Response.StatusCode.value__
        }
    }
    else {
        Write-Host "Could not bind user/ JumpCloudUsername did not exist in JC Directory"
    }
}
else{
    Write-Host "Could not find systemKey, aborting bind step"
}

# Restart Computer to update UI at login screen
Restart-Computer -Force