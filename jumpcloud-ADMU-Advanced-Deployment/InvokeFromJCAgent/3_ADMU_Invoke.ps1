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
$AutoBindJCUser = $true
$BindAsAdmin = $false # Bind user as admin (default False)
$JumpCloudAPIKey = '' # This field is required if the device is not eligible to use the systemContext API/ the systemContextBinding variable is set to false
$JumpCloudOrgID = '' # This field is required if you use a MTP API Key
$SetDefaultWindowsUser = $true # Set the default last logged on windows user to the JumpCloud user (default True)

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
# Define a hashtable of variables to validate
$booleanVariables = @{
    LeaveDomain           = $LeaveDomain
    ForceReboot           = $ForceReboot
    UpdateHomePath        = $UpdateHomePath
    AutoBindJCUser        = $AutoBindJCUser
    BindAsAdmin           = $BindAsAdmin
    SetDefaultWindowsUser = $SetDefaultWindowsUser
}

# Validate each variable in the hashtable
foreach ($key in $booleanVariables.Keys) {
    if ($booleanVariables[$key] -notin @($true, $false)) {
        Write-Host "[status] Required script variable '$key' not set or invalid, exiting..."
        exit 1
    }
}
# API key and ORGID validation
# The JumpCloud API Key can be null if the systemContextBinding is set to true
if ($systemContextBinding -eq $false) {
    if ([string]::IsNullOrEmpty($JumpCloudAPIKey)) {
        Write-Host "[status] Required script variable 'JumpCloudAPIKey' not set, exiting..."
        exit 1
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
    Write-Host "[status] CSV Imported."
    Write-Host "[status] CSV Imported, found $($ImportedCSV.Count) rows"
    Write-Host "[status] row headers: $($ImportedCSV[0].PSObject.Properties.Name)"
    # if "localComputerName", "SerialNumber", "JumpCloudUserName" are not in the CSV, exit
    if (!($ImportedCSV[0].PSObject.Properties.Name -contains "LocalComputerName") -or !($ImportedCSV[0].PSObject.Properties.Name -contains "SerialNumber") -or !($ImportedCSV[0].PSObject.Properties.Name -contains "JumpCloudUserName")) {
        Write-Host "[error] CSV file does not contain the required headers, exiting..."
        exit 1
    }
} catch {
    Write-Host "[error] Error importing CSV file, exiting..."
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
        Write-Host "[status] AD user path $($row.LocalPath) | Converting to JumpCloud User $($row.JumpCloudUserName)"
        $UsersToMigrate += [PSCustomObject]@{
            selectedUsername  = $row.SID
            JumpCloudUserName = $row.JumpCloudUserName
            JumpCloudUserID   = $row.JumpCloudUserID
            userPath          = $row.LocalPath
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
    If (($systemContextBinding -eq $true) -And ([string]::IsNullOrEmpty($user.JumpCloudUserID))) {
        Write-Error "[status] Could not migrate user, entry not found in CSV for JumpCloud UserID: $($user.selectedUsername); this field is required for systemContextBinding"
        exit 1
    }
}

#endregion dataImport

#region installADMU and required modules
# Install the latest ADMU from PSGallery
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# install Nuget if required:
$packageProviders = Get-PackageProvider | Select-Object name
if (!($packageProviders.name -contains "nuget")) {
    Write-Host "[status] NuGet not Found. Installing Package Provider"
    Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force
} else {
    Write-Host "[status] NuGet Module Found"
}
$packageProviders = Get-PackageProvider | Select-Object name
if ("nuget" -in $packageProviders.name) {
    write-host "[status] NuGet found. Importing into current session."
    Import-PackageProvider -Name NuGet -RequiredVersion 2.8.5.208 -Force
} else {
    write-host "[status] NuGet Module Not Found"
}

$requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
foreach ($module in $requiredModules) {
    $latestModule = Find-Module -Name $module -ErrorAction SilentlyContinue
    $installedModule = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue
    if (-NOT $installedModule) {
        Write-Host "[status] $module module not found, installing..."
        try {
            Install-Module $module -Force
        } catch {
            throw "[error] Failed to install $module module"
        }
    } else {
        # update the module if it's not the latest version
        if ($latestModule.Version -ne $installedModule.Version) {
            Write-Host "[status] $module module found, updating..."
            try {
                Uninstall-Module -Name $module -AllVersions
                Install-Module $module -Force

            } catch {
                throw "[error] Failed to update $module module, exiting..."
            }
        } else {
            Write-Host "[status] $module module is up to date"
        }
    }
}

# check that the module was imported
$module = Import-Module JumpCloud.ADMU -Force -ErrorAction SilentlyContinue
$module = Get-Module JumpCloud.ADMU
if ($null -eq $module) {
    Write-Host "[error] Failed to import JumpCloud ADMU module, exiting..."
    exit 1
} else {
    Write-Host "[status] JumpCloud ADMU module imported successfully; running version $($module.Version)"
}
# wait just a moment to ensure the ADMU was downloaded from PSGallery
start-sleep -Seconds 5

#endregion installADMU
# Run ADMU
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

# If multiple users are planned to be migrated: set the force reboot / leave domain options to false:
if ($UsersToMigrate) {
    #region logoffUsers
    # Query User Sessions & logoff
    # get rid of the > char & break out into a CSV type object
    $loggedInUsers = (quser) -replace '^>', ' ' | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
    # create a list for users
    $processedUsers = @()
    foreach ($obj in $loggedInUsers) {
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
    Write-host "[status] Logging off users..."
    foreach ($user in $UsersList) {
        If (($user.username)) {
            write-host "[status] Logging off user: $($user.username) with ID: $($user.ID)"
            # Force Logout
            logoff.exe $($user.ID)
        }
    }
    #endregion logoffUsers
    if ($LeaveDomain) {
        $LeaveDomain = $false
        Write-Host "[status] The Domain will attempt to be un-joined for the last user migrated on this system"
        $LeaveDomainAfterMigration = $true
    }

    # if you force with the JumpCloud command, the results will never be written to the console, we always want to reboot/shutdown with the built in commands.
    if ($ForceReboot) {
        $ForceReboot = $false
        Write-Host "[status] The system will $postMigrationBehavior after the last user is migrated"
        $ForceRebootAfterMigration = $true
    }
} else {
    Write-Host "[status] No users to migrate, exiting..."
    exit 1
}

#region migration
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
        AutoBindJCUser        = $AutoBindJCUser
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
    If ($systemContextBinding -eq $true) {
        # remove the binding parameters from the $migrationParams
        $migrationParams.Remove('AutoBindJCUser')
        $migrationParams.Remove('JumpCloudAPIKey')
        $migrationParams.Remove('JumpCloudOrgID')
        # add the systemContextAPI parameters to the $migrationParams
        $migrationParams.Add('systemContextBinding', $true)
        $migrationParams.Add('JumpCloudUserID', $user.JumpCloudUserID)
    }
    # Start the migration
    Write-Host "[status] Begin Migration for JumpCloudUser: $($user.JumpCloudUserName)"

    try {
        # Start the migration
        Start-Migration @migrationParams
        Write-Host "[status] Migration completed successfully for user: $($user.JumpCloudUserName)"
        #region post-migration
        # Add any addition code here to modify the user post-migration
        # The migrated user home directory should be set to the $user.userPath variable
        #endregion post-migration
    } catch {
        Write-Host "[status] Migration failed for user: $($user.JumpCloudUserName), exiting..."
        Write-Host "[status] Error: $($_.Exception.Message)"
        exit 1
    }
}
#endregion migration

# Un-manage the device from Intune:
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

#region restart/shutdown
# If force restart was specified, we kick off a command to initiate the restart
# this ensures that the JumpCloud commands reports a success
if ($ForceRebootAfterMigration) {
    if ($systemContextBinding -eq $true) {
        # wait 20 seconds after migration to ensure the agent has time to associate the user to the device
        Start-Sleep 20
        switch ($postMigrationBehavior) {
            'shutdown' {
                Write-Host "[status] Shutting down the system with PowerShell..."
                Stop-Computer -ComputerName localhost -force
            }
            'restart' {
                Write-Host "[status] Restarting the system with PowerShell..."
                Restart-Computer -ComputerName localhost -force
            }
        }
    } else {
        Write-Host "[status] Restarting system using JumpCloud API..."
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
}
#endregion restart/shutdown
exit 0
