################################################################################
# Update Variables Below
################################################################################

# get the CSV from the temp directory
$csvName = "JumpCloud-ADMU.csv"

# ADMU vars
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $true
$UpdateHomePath = $false
$AutobindJCUser = $true
$BindAsAdmin = $false # Bind user as admin (default False)
$JumpCloudAPIKey = 'YOUR_API_KEY'
$JumpCloudOrgID = 'YOUR_ORG_ID' # This field is required if you use a MTP API Key
$SetDefaultWindowsUser = $true # Set the default last logged on windows user to the JumpCloud user (default True)

# Option to shutdown or restart
# Restarting the system is the default behavior
# If you want to shutdown the system, set the postMigrationBehavior to Shutdown
# The 'shutdown' behavior performs a shutdown of the system in a much faster manner than 'restart' which can take 5 mins form the time the command is issued
$postMigrationBehavior = 'Restart' # Restart or Shutdown

# Option to remove the existing MDM
$removeMDM = $true # Remove the existing MDM (default True)

################################################################################
# Do not edit below
################################################################################

# validate postMigrationBehavior
if ($postMigrationBehavior -notin @('Restart', 'Shutdown')) {
    Write-Host "[status] Invalid postMigrationBehavior specified, exiting..."
    exit 1
} else {
    # set the postMigrationBehavior to lower case and continue
    $postMigrationBehavior = $postMigrationBehavior.ToLower()
}

# get the CSV data from the temp directory
$csvDirectory = "$env:TEMP\$csvName"
# import the CSV
$ImportedCSV = Import-Csv -Path $csvDirectory

# define list of user we want to migrate
$UsersToMigrate = @()

$computerName = $env:COMPUTERNAME
$serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber

write-host "[status] Computer Name: $($computerName)"
write-host "[status] Serial Number: $($serialNumber)"
# Find user to be migrated
foreach ($row in $ImportedCSV) {
    if (($row.LocalComputerName -eq ($computerName)) -AND ($row.SerialNumber -eq $serialNumber) -AND ($row.JumpCloudUserName -ne '')) {
        Write-Host "[status] Imported entry for $($row.LocalPath) | Converting to JumpCloud User $($row.JumpCloudUserName)"
        $UsersToMigrate += [PSCustomObject]@{
            selectedUsername  = $row.SID
            jumpcloudUserName = $row.JumpCloudUserName
        }
    }
}

# if the $UsersToMigrate is empty, exit
If ($UsersToMigrate.Count -eq 0) {
    Write-Host "[status] No users to migrate, exiting..."
    exit 1
}

# validate users to be migrated
foreach ($user in $UsersToMigrate) {
    # Validate parameter are not empty:
    If ([string]::IsNullOrEmpty($user.JumpCloudUserName)) {
        Write-Error "[status] Could not migrate user, entry not found in CSV for JumpCloud Username: $($user.selectedUsername)"
        exit 1
    }
}

# Install the latest ADMU from PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$latestADMUModule = Find-Module -Name JumpCloud.ADMU -ErrorAction SilentlyContinue
$installedADMUModule = Get-InstalledModule -Name JumpCloud.ADMU -ErrorAction SilentlyContinue
if (-NOT $installedADMUModule) {
    Write-Host "[status] JumpCloud ADMU module not found, installing..."
    Install-Module JumpCloud.ADMU -Force
} else {
    # update the module if it's not the latest version
    if ($latestADMUModule.Version -ne $installedADMUModule.Version) {
        Write-Host "[status] JumpCloud ADMU module found, updating..."
        Uninstall-Module -Name Jumpcloud.ADMU -AllVersions
        Install-Module JumpCloud.ADMU -Force
    } else {
        Write-Host "[status] JumpCloud ADMU module is up to date"
    }
}



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
    if ($lastUser -eq $user) {
        # If we are migrating the last user (or only user if single migration), we can leave the domain:
        Write-Host "[status] Migrating last user for this system..."
        #TODO: switch to form to de-clutter
        if ($LeaveDomainAfterMigration) {
            if ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
                Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $true -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -BindAsAdmin $BindAsAdmin -SetDefaultWindowsUser $SetDefaultWindowsUser -adminDebug $true
            } else {
                Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -LeaveDomain $true -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -BindAsAdmin $BindAsAdmin -JumpCloudOrgID $JumpCloudOrgID -SetDefaultWindowsUser $SetDefaultWindowsUser -adminDebug $true
            }
        } else {
            if ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
                Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -BindAsAdmin $BindAsAdmin -SetDefaultWindowsUser $SetDefaultWindowsUser -adminDebug $true
            } else {
                Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -BindAsAdmin $BindAsAdmin -JumpCloudOrgID $JumpCloudOrgID -SetDefaultWindowsUser $SetDefaultWindowsUser -adminDebug $true
            }
        }
    } else {
        if ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
            Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -BindAsAdmin $BindAsAdmin -SetDefaultWindowsUser $SetDefaultWindowsUser -adminDebug $true
        } else {
            Start-Migration -JumpCloudUserName $user.JumpCloudUserName -SelectedUserName $user.selectedUsername -TempPassword $TempPassword -UpdateHomePath $UpdateHomePath -AutobindJCUser $AutobindJCUser -JumpCloudAPIKey $JumpCloudAPIKey -BindAsAdmin $BindAsAdmin -JumpCloudOrgID $JumpCloudOrgID -SetDefaultWindowsUser $SetDefaultWindowsUser -adminDebug $true
        }

    }
}

# Remove the existing MDM
if ($removeMDM) {
    # get the raw content from the script
    $rawGitHubContentUrl = "https://raw.githubusercontent.com/TheJumpCloud/support/refs/heads/master/scripts/windows/remove_windowsMDM.ps1"
    # download the script to the temp directory
    $scriptPath = "$env:TEMP\remove_windowsMDM.ps1"
    Invoke-WebRequest -Uri $rawGitHubContentUrl -OutFile $scriptPath
    # run the script from the file
    # Execute the script
    & $scriptPath

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
    if ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
        $headers = @{
            "x-api-key" = $JumpCloudAPIKey
        }
    } else {
        $headers = @{
            "x-api-key" = $JumpCloudAPIKey
            "x-org-id"  = $JumpCloudOrgID
        }
    }
    write-host "[status] invoking $postMigrationBehavior command through JumpCloud agent, this may take a moment..."
    $response = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systems/$($systemKey)/command/builtin/$postMigrationBehavior" -Method POST -Headers $headers
    if ($response.queueId) {
        Write-Host "[status] $postMigrationBehavior command was successful"
    } else {
        Write-Host "[status] $postMigrationBehavior command was not successful, please $postMigrationBehavior manually"
        exit 1
    }
}
exit 0
