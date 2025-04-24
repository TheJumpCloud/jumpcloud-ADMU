# This script is designed to be run from the JumpCloud Agent and uploaded to a
# JumpCloud Command
# The script will run the ADMU command to migrate a user to JumpCloud
################################################################################
# Update Variables Below
################################################################################

# CSV or Github input
$dataSource = 'csv' # csv or github

# CSV variables only required if the dataSource is set to 'csv' this is the name of the CSV uploaded to the JumpCloud command
$csvName = 'jcdiscovery.csv'

# Github variables only required if dataSource is set to 'github' and the csv is stored in a remote repo
$GitHubUsername = ''
$GitHubToken = '' # https://github.com/settings/tokens needs token to write/create repo
$GitHubRepoName = 'Jumpcloud-ADMU-Discovery'

# ADMU variables
$TempPassword = 'Temp123!Temp123!'
$LeaveDomain = $true
$ForceReboot = $true
$UpdateHomePath = $false
$AutobindJCUser = $true
$BindAsAdmin = $false # Bind user as admin (default False)
$JumpCloudAPIKey = '' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false
$JumpCloudOrgID = '' # This field is required if you use a MTP API Key
$SetDefaultWindowsUser = $true # Set the default last logged on windows user to the JumpCloud user (default True)

# Option to shutdown or restart
# Restarting the system is the default behavior
# If you want to shutdown the system, set the postMigrationBehavior to Shutdown
# The 'shutdown' behavior performs a shutdown of the system in a much faster manner than 'restart' which can take 5 mins form the time the command is issued
$postMigrationBehavior = 'Restart' # Restart or Shutdown

# option to bind using the systemContext API
$systemContextBinding = $true # Bind using the systemContext API (default False)
# If you want to bind using the systemContext API, set the systemContextBinding to true
# The systemContextBinding option is only available for devices that have enrolled a device using a JumpCloud Administrators Connect Key
# for more information, see the JumpCloud documentation: https://docs.jumpcloud.com/api/2.0/index.html#section/System-Context
# this script will throw an error '3' if the systemContext API is not available for the system

################################################################################
# Do not edit below
################################################################################
#region validation

# validate dataSource
if ($dataSource -notin @('csv', 'github')) {
    Write-Host "[status] Invalid data source specified, exiting..."
    exit 1
}

# validate postMigrationBehavior
if ($postMigrationBehavior -notin @('Restart', 'Shutdown')) {
    Write-Host "[status] Invalid postMigrationBehavior specified, exiting..."
    exit 1
} else {
    # set the postMigrationBehavior to lower case and continue
    $postMigrationBehavior = $postMigrationBehavior.ToLower()
}

# validate the systemContextBinding param
if ($systemContextBinding -notin @($true, $false)) {
    Write-Host "[status] Invalid systemContextBinding specified, exiting..."
    exit 1
}
# validate the required ADMU parameters:
# validate tempPassword is not null
if ([string]::IsNullOrEmpty($TempPassword)) {
    Write-Host "[status] Required script variable 'TempPassword' not set, exiting..."
    exit 1
}
# validate that leaveDomain is a boolean
if ($LeaveDomain -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'LeaveDomain' not set, exiting..."
    exit 1
}
# validate that forceReboot is a boolean
if ($ForceReboot -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'ForceReboot' not set, exiting..."
    exit 1
}
# validate that updateHomePath is a boolean
if ($UpdateHomePath -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'UpdateHomePath' not set, exiting..."
    exit 1
}
# validate that autobindJCUser is a boolean
if ($AutobindJCUser -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'AutobindJCUser' not set, exiting..."
    exit 1
}
# validate that bindAsAdmin is a boolean
if ($BindAsAdmin -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'BindAsAdmin' not set, exiting..."
    exit 1
}
# validate that setDefaultWindowsUser is a boolean
if ($SetDefaultWindowsUser -notin @($true, $false)) {
    Write-Host "[status] Required script variable 'SetDefaultWindowsUser' not set, exiting..."
    exit 1
}
# API key and ORGID validation
# The JumpCloud API Key can be null if the systemContextBinding is set to true
if ($systemContextBinding -eq $false) {
    if ([string]::IsNullOrEmpty($JumpCloudAPIKey)) {
        Write-Host "[status] Required script variable 'JumpCloudAPIKey' not set, exiting..."
        exit 1
    }
}

# if the systemContextBinding is set to true, the JumpCloudAPIKey is not required but the SystemKey needs to exist:
if ($systemContextBinding -eq $true) {
    $getSystem = Invoke-SystemContextAPI -method 'GET' -endpoint 'systems'
    if ($getSystem.id) {
        Write-Host "[status] The systemContext API is available for this system, the system context API will be used for binding"
        Write-Host "[status] SystemID: $($getSystem.id)"
        Write-Host "[status] Hostname: $($getSystem.hostname)"
        $validatedSystemContextAPI = $true
        $validatedSystemID = $getSystem.id
    } else {
        $validatedSystemContextAPI = $false
        Write-Host "[status] The systemContext API is not available for this system, please use the standard binding method"
        Write-Error "Could not bind using the systemContext API, please use the standard binding method"
        exit 3
    }
}
#endregion validation

#region dataImport
switch ($dataSource) {
    'csv' {
        if (-not $csvName) {
            Write-Host "[status] Required script variable 'csvName' not set, exiting..."
            exit 1
        }
        # check if the CSV file exists
        # get the CSV data from the temp directory
        $discoveryCSVLocation = "C:\Windows\Temp\$csvName"
        if (-not (Test-Path -Path $discoveryCSVLocation)) {
            Write-Host "[status] CSV file not found, exiting..."
            exit 1
        }
    }
    'github' {
        # check if the GitHub token is set
        if (-not $GitHubToken) {
            Write-Host "[status] Required script variable 'GitHubToken' not set, exiting..."
            exit 1
        }
        # check if the GitHub username is set
        if (-not $GitHubUsername) {
            Write-Host "[status] Required script variable 'GitHubUsername' not set, exiting..."
            exit 1
        }

        # Create the GitHub credential set
        $password = ConvertTo-SecureString "$GitHubToken" -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential ($GitHubUsername, $password)

        # set working directory for GitHub csv
        $windowsTemp = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
        $workingDir = $windowsTemp
        $discoveryCSVLocation = $workingDir + '\jcdiscovery.csv'

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
        $jcdiscoverycsv = (Get-GitHubContent -OwnerName $GitHubUsername -RepositoryName $GitHubRepoName -BranchName 'main' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Entries | Where-Object { $_.name -match 'jcdiscovery.csv' } | Select-Object name, download_url
        New-Item -ItemType Directory -Force -Path $workingDir | Out-Null
        $dlname = ($workingDir + '\jcdiscovery.csv')
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $jcdiscoverycsv.download_url -OutFile $dlname
    }
}

# Import the CSV & check for one row per system
try {
    $ImportedCSV = Import-Csv -Path $discoveryCSVLocation
} catch {
    Write-Host "[status] Error importing CSV file, exiting..."
    exit 1
}

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
            jumpcloudUserID   = $row.JumpCloudUserID
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

#endregion dataImport

#region installADMU
# Install the latest ADMU from PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$latestADMUModule = Find-Module -Name JumpCloud.ADMU -ErrorAction SilentlyContinue
$installedADMUModule = Get-InstalledModule -Name JumpCloud.ADMU -ErrorAction SilentlyContinue
if (-NOT $installedADMUModule) {
    Write-Host "[status] JumpCloud ADMU module not found, installing..."
    try {
        Install-Module JumpCloud.ADMU -Force
    } catch {
        throw "Failed to install JumpCloud ADMU module"
    }
} else {
    # update the module if it's not the latest version
    if ($latestADMUModule.Version -ne $installedADMUModule.Version) {
        Write-Host "[status] JumpCloud ADMU module found, updating..."
        try {
            Uninstall-Module -Name Jumpcloud.ADMU -AllVersions
            Install-Module JumpCloud.ADMU -Force

        } catch {
            throw "[status] Failed to update JumpCloud ADMU module, exiting..."
        }
    } else {
        Write-Host "[status] JumpCloud ADMU module is up to date"
    }
}

# wait just a moment to ensure the ADMU was downloaded from PSGallery
start-sleep -Seconds 5

#endregion installADMU

#region logoffUsers
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

    # if you force with the JumpCloud command, the results will never be written to the console, we always want to reboot/shutdown with the built in commands.
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
    # Check if the user is the last user in the list
    $isLastUser = ($user -eq $lastUser)
    # the domain should only be left for the last user or the only user if there is only one
    $leaveDomainParam = if ($isLastUser -and $LeaveDomainAfterMigration) { $true } else { $false }
    # Create a hashtable for the migration parameters
    $migrationParams = @{
        JumpCloudUserName     = $user.JumpCloudUserName
        SelectedUserName      = $user.selectedUsername
        TempPassword          = $TempPassword
        UpdateHomePath        = $UpdateHomePath
        AutobindJCUser        = $AutobindJCUser
        JumpCloudAPIKey       = $JumpCloudAPIKey
        BindAsAdmin           = $BindAsAdmin
        SetDefaultWindowsUser = $SetDefaultWindowsUser
        LeaveDomain           = $leaveDomainParam
        adminDebug            = $true
    }
    # Add JumpCloudOrgID if it's not null or empty
    # This is required if you are using a MTP API Key
    If ([string]::IsNullOrEmpty($JumpCloudOrgID)) {
        $migrationParams.Remove('JumpCloudOrgID')
    } else {
        $migrationParams.Add('JumpCloudOrgID', $JumpCloudOrgID)
    }
    # if the systemContextAPI has been validated, remove the binding parameters from the $migrationParams
    If ($validatedSystemContextAPI) {
        # remove the binding parameters from the $migrationParams
        $migrationParams.Remove('AutobindJCUser')
        $migrationParams.Remove('BindAsAdmin')
        $migrationParams.Remove('JumpCloudAPIKey')
        $migrationParams.Remove('JumpCloudOrgID')

    }
    # Start the migration
    Write-Host "[status] Begin Migration for user: $($user.selectedUsername) -> $($user.JumpCloudUserName)"

    Start-Migration @migrationParams

    # Check if the migration was successful
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[status] Migration failed for user: $($user.JumpCloudUserName), exiting..."
        exit 1
    } else {
        Write-Host "[status] Migration completed successfully for user: $($user.JumpCloudUserName)"
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
