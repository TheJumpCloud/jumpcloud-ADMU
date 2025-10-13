# This script is designed to be run from the JumpCloud Console as a command. It
# will be invoked by the JumpCloud Agent on the target system.
# The script will run the ADMU command to migrate a user to JumpCloud
################################################################################
# Update Variables Below
################################################################################
#region variables
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
################################################################################
# Do not edit below
################################################################################
#region functionDefinitions
Function Confirm-MigrationParameter {
    [CmdletBinding()]
    param(
        # --- Data Source Parameters ---
        [ValidateSet('csv', 'github')]
        [string]$dataSource = 'csv',

        [string]$csvName = 'jcdiscovery.csv',
        [string]$GitHubUsername = '',
        [string]$GitHubToken = '',
        [string]$GitHubRepoName = 'Jumpcloud-ADMU-Discovery',

        # --- ADMU Core Parameters ---
        [string]$TempPassword = 'Temp123!Temp123!',
        [bool]$LeaveDomain = $true,
        [bool]$ForceReboot = $true,
        [bool]$UpdateHomePath = $false,
        [bool]$AutoBindJCUser = $true,
        [bool]$BindAsAdmin = $false,
        [bool]$SetDefaultWindowsUser = $true,

        # --- JumpCloud API Parameters ---
        [bool]$systemContextBinding = $false,
        [string]$JumpCloudAPIKey = 'YOURAPIKEY',
        [string]$JumpCloudOrgID = 'YOURORGID',
        [bool]$ReportStatus = $false,

        # --- Post-Migration Behavior ---
        [ValidateSet('Restart', 'Shutdown')]
        [string]$postMigrationBehavior = 'Restart',

        [bool]$removeMDM = $false
    )

    # --- Custom Validation Logic ---

    # 1. Validate parameters based on the selected data source
    if ($dataSource -eq 'csv') {
        if ([string]::IsNullOrWhiteSpace($csvName)) {
            throw "Parameter Validation Failed: When dataSource is 'csv', the 'csvName' parameter cannot be empty."
        }
    } elseif ($dataSource -eq 'github') {
        if ([string]::IsNullOrWhiteSpace($GitHubUsername)) {
            throw "Parameter Validation Failed: When dataSource is 'github', the 'GitHubUsername' parameter cannot be empty."
        }
        if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
            throw "Parameter Validation Failed: When dataSource is 'github', the 'GitHubToken' parameter cannot be empty."
        }
        if ([string]::IsNullOrWhiteSpace($GitHubRepoName)) {
            throw "Parameter Validation Failed: When dataSource is 'github', the 'GitHubRepoName' parameter cannot be empty."
        }
    }

    # 2. Validate TempPassword is not empty
    if ([string]::IsNullOrEmpty($TempPassword)) {
        throw "Parameter Validation Failed: The 'TempPassword' parameter cannot be empty."
    }

    # 3. Conditionally validate JumpCloud API parameters
    # This check is crucial. It runs if the user relies on the default systemContextBinding=$false or sets it explicitly.
    if (-not $systemContextBinding) {
        if ([string]::IsNullOrWhiteSpace($JumpCloudAPIKey) -or $JumpCloudAPIKey -eq 'YOURAPIKEY') {
            throw "Parameter Validation Failed: 'JumpCloudAPIKey' must be set to a valid key when 'systemContextBinding' is false."
        }
        if ([string]::IsNullOrWhiteSpace($JumpCloudOrgID) -or $JumpCloudOrgID -eq 'YOURORGID') {
            throw "Parameter Validation Failed: 'JumpCloudOrgID' must be set to a valid ID when 'systemContextBinding' is false."
        }
    }

    # If all validation checks pass, return true.
    return $true
}
Function Confirm-ExecutionPolicy {
    # this checks the execution policy
    # returns True/False
    begin {
        $success = $true
        $curExecutionPolicy = Get-ExecutionPolicy -List
        $lines = $curExecutionPolicy -split "`n" | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^-{5}' -and $_ -notmatch 'Scope ExecutionPolicy' }
        $policies = [PSCustomObject]@{
            MachinePolicy = ""
            UserPolicy    = ""
            Process       = ""
            CurrentUser   = ""
            LocalMachine  = ""
        }

        $regex = '@\{Scope=(.+?); ExecutionPolicy=(.+?)\}'
    }
    process {
        try {
            foreach ($line in $lines) {
                if ($line -match $regex) {
                    $scope = $matches[1]
                    $executionPolicy = $matches[2].Trim()
                    switch ($scope) {
                        "MachinePolicy" { $policies.MachinePolicy = $executionPolicy }
                        "UserPolicy" { $policies.UserPolicy = $executionPolicy }
                        "Process" { $policies.Process = $executionPolicy }
                        "CurrentUser" { $policies.CurrentUser = $executionPolicy }
                        "LocalMachine" { $policies.LocalMachine = $executionPolicy }
                    }
                }
            }
            # if the machinePolicy is set to Restricted, AllSigned or RemoteSigned, the ADMU script can not run
            If (($policies.MachinePolicy -eq "Restricted") -or
                ($policies.MachinePolicy -eq "AllSigned") -or
                ($policies.MachinePolicy -eq "RemoteSigned")) {
                Throw "Machine Policy is set to $($policies.MachinePolicy), this script can not change the Machine Policy because it's set by Group Policy. You need to change this in the Group Policy Editor and likely enable scripts to be run"
                # Throw "Machine Policy is set to $($policies.MachinePolicy)"
                $success = $false

            }
            If ($policies.MachinePolicy -eq "Unrestricted") {
                Write-Host "[status] Machine Policy is set to Unrestricted, no changes made."
                $success = $true
                return
            }
            # If the Process policy is set to Restricted, AllSigned or RemoteSigned, we need to change it to Bypass
            if (($policies.Process -eq "Restricted") -or
                ($policies.Process -eq "AllSigned") -or
                ($policies.Process -eq "RemoteSigned") -or
                ($policies.Process -eq "Undefined")) {
                Write-Host "[status] Local Machine Policy is set to $($policies.LocalMachine), setting to Bypass"
                try {
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
                } catch {
                    Throw "Failed to set Process execution policy to Bypass."
                    $success = $false
                }
            } else {
                Write-Host "[status] Local Machine Policy is set to $($policies.LocalMachine), no changes made."
            }
            # If the localMachine policy is set to Restricted, AllSigned or RemoteSigned, we need to change it to Bypass
            if (($policies.LocalMachine -eq "Restricted") -or
                ($policies.LocalMachine -eq "AllSigned") -or
                ($policies.LocalMachine -eq "RemoteSigned") -or
                ($policies.LocalMachine -eq "Undefined")) {
                Write-Host "[status] Local Machine Policy is set to $($policies.LocalMachine), setting to Bypass"
                try {
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
                } catch {
                    Throw "Failed to set LocalMachine execution policy to Bypass."
                    $success = $false
                }
            } else {
                Write-Host "[status] Local Machine Policy is set to $($policies.LocalMachine), no changes made."
            }
        } catch {
            Throw "Exception occurred in Confirm-ExecutionPolicy: $($_.Exception.Message)"
            $success = $false
        }
    }
    end {
        return $success
    }
}
Function Confirm-RequiredModule {
    [CmdletBinding()]
    param (
        [Parameter()]
        [system.string[]]
        $requiredModules = @('PowerShellGet', 'JumpCloud.ADMU')
    )
    # this checks the installed modules
    # returns True/False
    # set the security protocol to TLS 1.2
    begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $nugetRequiredVersion = "2.8.5.208"
        $allSuccess = $true
    }
    process {
        $nugetSuccess = $false
        $packageProviders = Get-PackageProvider -Force | Select-Object name
        if (!($packageProviders.name -contains "nuget")) {
            Write-Host "[status] NuGet not Found. Installing Package Provider"
            try {
                $installResponse = Install-PackageProvider -Name NuGet -RequiredVersion $nugetRequiredVersion -Force
                Write-Host "[status] NuGet Module was successfully installed."
            } catch {
                $nugetURL = "https://onegetcdn.azureedge.net/providers/nuget-$($nugetRequiredVersion).package.swidtag"
                $nugetResponse = Invoke-WebRequest $nugetURL
                If ($nugetResponse.StatusCode -ne 200) {
                    Throw "The NuGet package provider could not be installed from $nugetURL."
                    $allSuccess = $false
                }
            }
        } else {
            Write-Host "[status] NuGet Module was previously installed, skipping installation."
        }
        # import the NuGet module
        try {
            write-host "[status] NuGet found. Importing into current session."
            $importResponse = Import-PackageProvider -Name NuGet -RequiredVersion $nugetRequiredVersion -Force
            write-host "[status] NuGet version $($ImportResponse.Version.ToString()) successfully imported."
            $nugetSuccess = $true
        } catch {
            Throw "Could not import Nuget into the current session."
            $allSuccess = $false
        }
        # process the required modules
        foreach ($module in $requiredModules) {
            $moduleSuccess = $false
            $latestModule = Find-Module -Name $module -ErrorAction SilentlyContinue
            $installedModule = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue
            if (-NOT $installedModule) {
                Write-Host "[status] $module module not found, installing..."
                try {
                    Install-Module -Name $module -Force
                } catch {
                    Throw "Failed to install $module module"
                    $allSuccess = $false
                }
            } else {
                if ($latestModule.Version -ne $installedModule.Version) {
                    Write-Host "[status] $module module found, updating..."
                    try {
                        Uninstall-Module -Name $module -AllVersions
                        Install-Module -Name $module -Force
                    } catch {
                        Throw "Failed to update $module module, exiting..."
                        $allSuccess = $false
                    }
                } else {
                    Write-Host "[status] $module module is up to date"
                }
            }
            # Try to import the module
            try {
                Import-Module -Name $module -Force -ErrorAction Stop
                $imported = Get-Module -Name $module
                if ($null -eq $imported) {
                    Throw "Failed to import $module module."
                    $allSuccess = $false
                } else {
                    Write-Host "[status] $module module imported successfully; running version $($imported.Version)"
                    $moduleSuccess = $true
                }
            } catch {
                Throw "Failed to import $module module, exiting..."
                $allSuccess = $false
            }
        }
    }
    end {
        # Return true if all required modules and NuGet were installed/imported successfully
        if ($allSuccess -and $nugetSuccess) {
            return $true
        } else {
            return $false
        }
    }
}
Function Get-MigrationUsersFromCsv {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        # The full path to the discovery CSV file.
        [Parameter(Mandatory = $true)]
        [string]$csvPath,
        [Parameter(Mandatory = $true)]
        [boolean]$systemContextBinding
    )

    begin {
        # 1. --- FILE AND HEADER VALIDATION ---
        if (-not (Test-Path -Path $csvPath -PathType Leaf)) {
            Throw "Validation Failed: The CSV file was not found at: '$csvPath'."
        }
        $ImportedCSV = Import-Csv -Path $csvPath -ErrorAction Stop
    }
    process {
        $requiredHeaders = @("LocalComputerName", "SerialNumber", "JumpCloudUserName", "SID", "LocalPath")
        $csvHeaders = $ImportedCSV[0].PSObject.Properties.Name
        foreach ($header in $requiredHeaders) {
            if ($header -notin $csvHeaders) {
                throw "Validation Failed: The CSV is missing the required header: '$header'."
            }
        }

        # 2. --- DUPLICATE SID VALIDATION ---
        $groupedByDevice = $ImportedCSV | Group-Object -Property 'LocalComputerName'
        foreach ($device in $groupedByDevice) {
            $duplicateSids = $device.Group | Group-Object -Property 'SID' | Where-Object { $_.Count -gt 1 }
            if ($duplicateSids) {
                throw "Validation Failed: Duplicate SID '$($duplicateSids[0].Name)' found for LocalComputerName '$($device.Name)'."
            }
        }

        # 3. --- FIND AND BUILD USER OBJECTS ---
        $usersToMigrate = @()
        $computerName = $env:COMPUTERNAME
        $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber

        foreach ($row in $ImportedCSV) {
            # --- Filter for this machine and create the custom object ---
            if (($row.LocalComputerName -eq $computerName) -and ($row.SerialNumber -eq $serialNumber)) {
                # If a non-empty JumpCloudUsername is provided, continue with further validation
                If (-not [string]::IsNullOrWhiteSpace($row.JumpCloudUserName)) {
                    # Validate if JumpCloudUserID is not null or empty when the systemContextBinding option is enabled
                    if ($systemContextBinding -and [string]::IsNullOrWhiteSpace($row.JumpCloudUserID)) {
                        throw "VALIDATION FAILED: on row $rowNum : 'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
                    }
                    # --- Row content validation ---
                    $requiredFields = "LocalPath", "SID"
                    foreach ($field in $requiredFields) {
                        if ([string]::IsNullOrWhiteSpace($row.$field)) {
                            throw "Validation Failed: Missing required data for field '$field'."
                        }
                    }
                    $usersToMigrate += [PSCustomObject]@{
                        selectedUsername  = $row.SID
                        LocalProfilePath  = $row.LocalPath
                        JumpCloudUserName = $row.JumpCloudUserName
                        JumpCloudUserID   = $row.JumpCloudUserID
                    }
                }
            }
        }
    }

    end {
        # 4. --- FINAL CHECK AND RETURN ---
        if ($usersToMigrate.Count -eq 0) {
            throw "Validation Failed: No users were found in the CSV matching this computer's name ('$computerName') and serial number ('$serialNumber')."
        }
        return $usersToMigrate
    }

}
#endregion functionDefinitions

#region validation
# validate dataSource
$confirmMigrationParameters = Confirm-MigrationParameter -dataSource $dataSource `
    -csvName $csvName `
    -GitHubUsername $GitHubUsername `
    -GitHubToken $GitHubToken `
    -GitHubRepoName $GitHubRepoName `
    -TempPassword $TempPassword `
    -LeaveDomain $LeaveDomain `
    -ForceReboot $ForceReboot `
    -UpdateHomePath $UpdateHomePath `
    -AutoBindJCUser $AutoBindJCUser `
    -BindAsAdmin $BindAsAdmin `
    -SetDefaultWindowsUser $SetDefaultWindowsUser `
    -systemContextBinding $systemContextBinding `
    -JumpCloudAPIKey $JumpCloudAPIKey `
    -JumpCloudOrgID $JumpCloudOrgID `
    -postMigrationBehavior $postMigrationBehavior `
    -removeMDM $removeMDM `
    -ReportStatus $ReportStatus
if ($confirmMigrationParameters) {
    Write-Host "[STATUS] Migration parameters validated successfully."
}

Confirm-ExecutionPolicy

Confirm-RequiredModule -requiredModules @('PowerShellForGitHub', 'JumpCloud.ADMU')
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

        Confirm-RequiredModule -requiredModules @('PowerShellForGitHub')

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


# Call the function and store the result (which is either an array of users or $null)
$UsersToMigrate = Get-MigrationUsersFromCsv -CsvPath $discoveryCSVLocation -systemContextBinding $systemContextBinding
#endregion validation
#### End CSV Validation ####

# Run ADMU

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

Write-Host "Starting validation for file: $CsvPath"

# Get the last user from the list to handle the LeaveDomain parameter correctly.
$lastUser = $UsersToMigrate | Select-Object -Last 1

# Loop through each user from the validated CSV and perform the migration.
foreach ($user in $UsersToMigrate) {
    # Check if the user is the last user in the list
    $isLastUser = ($user -eq $lastUser)
    # The domain should only be left for the last user or the only user if there is only one
    $leaveDomainParam = if ($isLastUser -and $LeaveDomainAfterMigration) { $true } else { $false }

    # Create a hashtable for the migration parameters.
    # NOTE: This assumes the CSV column 'LocalUsername' corresponds to the needed 'SelectedUserName'.
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
        ReportStatus          = $ReportStatus
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

    # Write output for AzureAD and LocalDomain status
    try {
        $ADStatus = dsregcmd.exe /status
        foreach ($line in $ADStatus) {
            if ($line -match "AzureADJoined : ") {
                $AzureADStatus = ($line.TrimStart('AzureADJoined : '))
            }
            if ($line -match "DomainJoined : ") {
                $LocalDomainStatus = ($line.TrimStart('DomainJoined : '))
            }
        }
    } catch {
        Write-Host "[status] Error: $($_.Exception.Message)"
    }
    Write-Host "Domain status before migration:"
    Write-Host "[status] Azure/EntraID status: $AzureADStatus"
    Write-Host "[status] Local domain status: $LocalDomainStatus"
    # Start the migration
    Write-Host "[status] Begin Migration for JumpCloudUser: $($user.JumpCloudUserName)"
    Start-Migration @migrationParams
    Write-Host "[status] Migration completed successfully for user: $($user.JumpCloudUserName)"
    #region post-migration
    # Add any addition code here to modify the user post-migration
    # The migrated user home directory should be set to the $user.userPath variable
    #endregion post-migration
}
Write-Host "`nAll user migrations have been processed."
#endregion migration

#region removeMDM
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
#endregion removeMDM

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