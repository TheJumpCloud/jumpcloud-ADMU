################################################################################
# Update Variables Below
################################################################################

# Github vars
$GHUsername = ''
$GHToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GHRepoName = 'Jumpcloud-ADMU-Discovery'

# ADMU vars
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $true
$UpdateHomePath = $false
$AutobindJCUser = $true
$JumpCloudAPIKey = ''
$JumpCloudOrgID = '' # This field is required if you use a MTP API Key

################################################################################
# Do not edit below
################################################################################

# Create the GitHub credential set
$password = ConvertTo-SecureString "$GHToken" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($GHUsername, $password)

# set working directory for GitHub csv
$windowstemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
$workingdir = $windowstemp
$discoverycsvlocation = $workingdir + '\jcdiscovery.csv'

# Set security protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet -Force
# Install Module PowerShellForGitHub
if ($null -eq (Get-InstalledModule -Name "PowerShellForGitHub" -ErrorAction SilentlyContinue)) {
    Install-Module PowerShellForGitHub -Force
}

# Auth to github
Set-GitHubAuthentication -Credential $cred

# Download jcdiscovery.csv from GH
$jcdiscoverycsv = (Get-GitHubContent -OwnerName $GHUsername -RepositoryName $GHRepoName -BranchName 'main' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Entries | Where-Object { $_.name -match 'jcdiscovery.csv' } | Select-Object name, download_url
New-Item -ItemType Directory -Force -Path $workingdir | Out-Null
$dlname = ($workingdir + '\jcdiscovery.csv')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $jcdiscoverycsv.download_url -OutFile $dlname

# Import the CSV & check for one row per system
$ImportedCSV = Import-Csv -Path $discoverycsvlocation

# define list of user we want to migrate
$UsersToMigrate = @()

# Find user to be migrated
foreach ($row in $ImportedCSV) {
    if ($row.LocalComputerName -eq ($env:COMPUTERNAME)) {
        Write-Host "[status] Imported entry for $($row.LocalPath) | Converting to JumpCloud User $($row.JumpCloudUserName)"
        $UsersToMigrate += [PSCustomObject]@{
            selectedUsername  = $row.SID
            jumpcloudUserName = $row.JumpCloudUserName
        }
    }
}

# validate users to be migrated
foreach ($user in $UsersToMigrate) {
    # Validate parameter are not empty:
    If ([string]::IsNullOrEmpty($user.JumpCloudUserName)) {
        Write-Error "Could not migrate user, entry not found in CSV for JumpCloud Username: $($user.selectedUsername)"
        exit 1
    }
}

# Install the latest ADMU from PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-Module JumpCloud.ADMU -Force

# wait just a moment to ensure the ADMU was downloaded from PSGallery
start-sleep -Seconds 5

# Query User Sessions & logoff
# get rid of the > char & break out into a CSV type object
$quserResult = (quser) -replace '^>', ' ' | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
# create a list for users
$processedUsers = @()
foreach ($obj in $quserResult) {
    # if missing an entry for one of: USERNAME,SESSIONNAME,ID,STATE,IDLE TIME OR LOGON TIME, add a comma
    if ($obj.Split(',').Count -ne 6) {
        # Write-Host ($obj -replace '(^[^,]+)', '$1,')
        $processedUsers += ($obj -replace '(^[^,]+)', '$1,')
    } else {
        # Write-Host ($obj)
        $processedUsers += $obj
    }
}
$UsersList = $processedUsers | ConvertFrom-Csv
Write-host "[status] $($usersList.count) will be logged out"
foreach ($user in $UsersList) {
    If (($user.username)) {
        write-host "[status] Logging off user: $($user.username) with ID: $($user.ID)"
        # Force Logout
        logoff.exe $($user.ID)
    }
}
# Run ADMU
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

# If multiple users are planned to be migrated: set the force reboot / leave domain options to false:
if ($UsersToMigrate) {
    if ($LeaveDomain) {
        $LeaveDomain = $false
        Write-Host "[status] The Domain will be left for the last user migrated on this system"
        $LeaveDomainAfterMigration = $true
    }

    # if you force with the JumpCloud command , you are going to have a bad time.
    if ($ForceReboot) {
        $ForceReboot = $false
        Write-Host "[status] The system will be restarted after the last user is migrated"
        $ForceRebootAfterMigration = $true
    }
}

# Get the last user in the migration list
$lastUser = $($UsersToMigrate | Select-Object -Last 1)

# migrate each user
foreach ($user in $UsersToMigrate) {
    Write-Host "[status] Begin Migration for user: $($user.selectedUsername) -> $($user.JumpCloudUserName)"
    if (($lastUser -eq $user) -And ($LeaveDomainAfterMigration)) {
        # If we are migrating the last user (or only user if single migration), we can leave the domain:
        Write-Host "[status] Migrating last user for this system..."
        If ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
            # migrate with OrgID
            Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $LeaveDomainAfterMigration -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -JumpCloudOrgID -$JumpCloudOrgID
        } else {
            # migrate without OrgID
            Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $LeaveDomainAfterMigration -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey
        }
    } else {
        If ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
            # migrate with OrgID
            Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $LeaveDomainAfterMigration -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -JumpCloudOrgID -$JumpCloudOrgID

        } else {
            # migrate without OrgID
            Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $LeaveDomainAfterMigration -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey
        }
        Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $LeaveDomain -ForceReboot $ForceReboot -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey
    }
}

# If force restart was specified, we kick off a command to initiate the restart
# this ensures that the JumpCloud commands reports a success
if ($ForceRebootAfterMigration) {
    $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    if ([string]::IsNullOrEmpty($systemKey)) {
        Write-Host "JumpCloud SystemID could not be verified, exiting..."
        exit 1
    }
    $headers = @{}
    $headers.Add("x-api-key", $JumpCloudAPIKey)
    write-host "[status] invoking reboot command through JumpCloud"
    $response = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systems/$($systemKey)/command/builtin/shutdown" -Method POST -Headers $headers
}
exit 0