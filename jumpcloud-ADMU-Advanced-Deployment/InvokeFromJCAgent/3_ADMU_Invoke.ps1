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
Function Confirm-RequiredModule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [system.string[]]
        $requiredModules
    )
    # this checks the installed modules
    # returns True/False
    # set the security protocol to TLS 1.2
    begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $allSuccess = $true
    }
    process {

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
        # Return true if all required modules were installed/imported successfully
        if ($allSuccess) {
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
                # Validate if JumpCloudUserID is not null or empty
                if ($systemContextBinding -and [string]::IsNullOrWhiteSpace($row.JumpCloudUserID)) {
                    throw "VALIDATION FAILED: on row $rowNum : 'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
                }
                # --- Row content validation ---
                $requiredFields = "LocalPath", "SID", "JumpCloudUserName"
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

    end {
        # 4. --- FINAL CHECK AND RETURN ---
        if ($usersToMigrate.Count -eq 0) {
            throw "Validation Failed: No users were found in the CSV matching this computer's name ('$computerName') and serial number ('$serialNumber')."
        }
        return $usersToMigrate
    }

}
function Get-LatestADMUGUIExe {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        # The full path to the discovery CSV file.
        [Parameter(Mandatory = $false)]
        [string]$destinationPath = "C:\Windows\Temp"
    )

    begin {
        $owner = "TheJumpCloud"
        $repo = "jumpcloud-ADMU"
        $apiUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
    }

    process {
        try {
            Write-Host "Querying GitHub API for the latest '$repo' release..." -ForegroundColor Yellow

            # Get latest release data from the GitHub API
            $latestRelease = Invoke-RestMethod -Uri $apiUrl -ErrorAction Stop

            # Find the specific GUI executable asset
            $exeAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }

            if ($exeAsset) {
                $downloadUrl = $exeAsset.browser_download_url
                $fileName = $exeAsset.name
                $fullPath = Join-Path -Path $destinationPath -ChildPath $fileName

                Write-Host "Downloading '$fileName' (Version $($latestRelease.tag_name))..." -ForegroundColor Yellow

                Invoke-WebRequest -Uri $downloadUrl -OutFile $fullPath -ErrorAction Stop

                Write-Host "Download complete! File saved to '$fullPath'." -ForegroundColor Green
            } else {
                Throw "Could not find 'gui_jcadmu.exe' in the latest release."
            }
        } catch {
            Throw "Operation failed. The error was: $_"
        }
    }


}
function ConvertTo-ArgumentList {
    <#
    .SYNOPSIS
        Converts a hashtable into a list of command-line arguments.

    .DESCRIPTION
        This function iterates through a given hashtable and converts each key-value pair
        into a string formatted as "-Key:Value". It specifically handles boolean values
        by converting them to lowercase string literals (e.g., '$true', '$false') and
        skips any entries where the value is null or an empty string.

    .PARAMETER InputHashtable
        The hashtable to be converted into an argument list. This parameter is mandatory.


    .OUTPUTS
        [System.Collections.Generic.List[string]]
        A list of strings, where each string is a formatted command-line argument.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [hashtable]
        $InputHashtable
    )

    # Initialize a generic list to hold the formatted arguments.
    $argumentList = [System.Collections.Generic.List[string]]::new()

    # Iterate through each key-value pair in the input hashtable.
    foreach ($entry in $InputHashtable.GetEnumerator()) {
        # Only process entries where the value is not null or an empty string.
        if ($null -ne $entry.Value -and (-not ($entry.Value -is [string]) -or $entry.Value -ne '')) {
            $key = $entry.Key
            $value = $entry.Value

            # Format the value. Booleans are converted to lowercase string literals like '$true'.
            # Other types are used as-is (they will be converted to strings automatically).
            $formattedValue = if ($value -is [bool]) {
                '$' + $value.ToString().ToLower()
            } else {
                $value
            }

            # Construct the argument string in the format -Key:Value and add it to the list.
            $argument = "-{0}:{1}" -f $key, $formattedValue
            $argumentList.Add($argument)
        }
    }

    # Return the completed list of arguments.
    return $argumentList
}
function Get-JcadmuGuiSha256 {
    <#
    .SYNOPSIS
        Dynamically finds the latest JumpCloud ADMU release and retrieves the SHA256 hash from the asset's digest.

    .DESCRIPTION
        This function calls the GitHub API to find the most recent release for the TheJumpCloud/jumpcloud-ADMU repository.
        It then iterates through the release's assets to find 'gui_jcadmu.exe' and extracts the official SHA256 hash
        directly from the asset's 'digest' field. This is the most robust method as it relies on structured API data.

    .EXAMPLE
        PS C:\> Get-JcadmuGuiSha256

        TagName  SHA256
        -------  ------
        v2.8.10  e132d7942b3429b1993e016d977d66f0a398fd31625b0f90507cb1273f362ac6

    .OUTPUTS
        [PSCustomObject] An object containing the release tag name and the corresponding SHA256 hash.
    #>
    [CmdletBinding()]
    param()
    begin {
        $apiUrl = "https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases"
        $releases = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{ "Accept" = "application/vnd.github.v3+json" }
    }
    process {
        try {
            if ($null -eq $releases -or $releases.Count -eq 0) {
                throw "No releases were found for the repository."
                return
            }

            $latestRelease = $releases[0]
            $latestTag = $latestRelease.tag_name

            # Find the specific asset within the 'assets' array
            $targetAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }

            if ($targetAsset) {
                $digest = $targetAsset.digest

                if ($digest -and $digest.StartsWith('sha256:')) {
                    $sha256 = $digest.Split(':')[1]
                    return [PSCustomObject]@{
                        TagName = $latestTag
                        SHA256  = $sha256
                    }
                }
            } else {
                throw "Asset 'gui_jcadmu.exe' not found in the latest release (Tag: $latestTag)."
            }
        } catch {
            throw "An API error or network issue occurred: $_"
        }
    }


}
function Test-ExeSHA {
    param (
        [Parameter(Mandatory = $true)]
        [string]$filePath
    )
    process {
        if (-not (Test-Path -Path $filePath)) {
            Throw "The gui_jcadmu.exe file was not found at: '$filePath'."
        }
        $releaseSHA256 = Get-JcadmuGuiSha256
        $releaseSHA256 = $releaseSHA256.SHA256

        # Get the SHA256 of the local file
        $localFileHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()

        Write-Host "[status] Official SHA256: $releaseSHA256"
        Write-Host "[status] Local File SHA256:  $localFileHash"
        Write-Host "`nValidating the downloaded file against the official release hash..."

        if ($localFileHash -eq $releaseSHA256.ToLower()) {
            Write-Host "[status] SUCCESS: Hash validation passed! The local file matches the official release."
        } else {
            throw "[status] WARNING: HASH MISMATCH! The local file is different from the official release."
        }
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

$guiJcadmuPath = "C:\Windows\Temp\gui_jcadmu.exe" # Exe path

# Download the latest ADMU GUI executable
Get-LatestADMUGUIExe # Download the latest ADMU GUI executable

# Validate the downloaded file against the official release hash
Test-ExeSHA -filePath $guiJcadmuPath

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
    # Convert Migration Parameters to Argument List
    $convertedParams = ConvertTo-ArgumentList -InputHashtable $migrationParams
    # Get the Gui_jcadmu.exe path
    if (-not (Test-Path -Path $guiJcadmuPath)) {
        Throw "The gui_jcadmu.exe file was not found at: '$guiJcadmuPath'. Please ensure the file is present before running the migration."
    }
    # Do invoke Expression to call the ADMU command with the parameters
    Write-Host "[status] Executing migration command..."
    & $guiJcadmuPath $convertedParams


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
        $postMigrationBehavior = $postMigrationBehavior.ToLower() # Restart or Shutdown endpoint is case sensitive
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