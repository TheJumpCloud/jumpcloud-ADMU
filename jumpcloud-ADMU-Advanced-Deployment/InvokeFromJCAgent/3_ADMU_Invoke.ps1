# This script is designed to be run from the JumpCloud Console as a command. It
# will be invoked by the JumpCloud Agent on the target system.
# The script will run the ADMU command to migrate a user to JumpCloud
################################################################################
# Update Variables Below
################################################################################
#region variables

# Data source for migration users: "CSV" or "Description"
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
################################################################################
# Do not edit below
################################################################################
#region functionDefinitions
function Confirm-MigrationParameter {
    [CmdletBinding()]
    param(
        [ValidateSet('CSV', 'Description')]
        [string]$dataSource = 'Description',

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

        [ValidateSet('Restart', 'Shutdown')]
        [string]$postMigrationBehavior = 'Restart'
    )
    if ($dataSource -eq 'CSV') {
        if ([string]::IsNullOrWhiteSpace($csvName)) {
            throw "Parameter Validation Failed: When dataSource is 'CSV', the 'csvName' parameter cannot be empty."
        }
    }
    if ([string]::IsNullOrEmpty($TempPassword)) {
        throw "Parameter Validation Failed: The 'TempPassword' parameter cannot be empty."
    }
    # This check is crucial. It runs if the user relies on the default systemContextBinding=$false or sets it explicitly.
    if (-not $systemContextBinding) {
        if ([string]::IsNullOrWhiteSpace($JumpCloudAPIKey) -or $JumpCloudAPIKey -eq 'YOURAPIKEY') {
            throw "Parameter Validation Failed: 'JumpCloudAPIKey' must be set to a valid key when 'systemContextBinding' is false."
        }
        if ([string]::IsNullOrWhiteSpace($JumpCloudOrgID) -or $JumpCloudOrgID -eq 'YOURORGID') {
            throw "Parameter Validation Failed: 'JumpCloudOrgID' must be set to a valid ID when 'systemContextBinding' is false."
        }
    }
    return $true
}
function Get-MigrationUsers {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CSV', 'Description')]
        [string]$source,

        [Parameter(Mandatory = $false)]
        [string]$csvName = 'jcdiscovery.csv',

        [Parameter(Mandatory = $false)]
        [string]$GetSystemScriptPath = 'C:\Windows\Temp\Get-System.ps1',

        [Parameter(Mandatory = $true)]
        [boolean]$systemContextBinding
    )

    if ($source -eq 'CSV') {
        # CSV-based migration
        return Get-MigrationUsersFromCsv -csvName $csvName -systemContextBinding $systemContextBinding
    } elseif ($source -eq 'Description') {
        # System description-based migration
        return Get-MigrationUsersFromSystemDescription -GetSystemScriptPath $GetSystemScriptPath -systemContextBinding $systemContextBinding
    }
}

function Get-MigrationUsersFromCsv {
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
            throw "Validation Failed: The CSV file was not found at: '$csvPath'."
        }
        $ImportedCSV = Import-Csv -Path $csvPath -ErrorAction Stop
    }
    process {
        # Begin by processing the CSV content headers, these should include the required values
        $requiredHeaders = @("LocalComputerName", "SerialNumber", "JumpCloudUserName", "SID", "LocalPath")
        $csvHeaders = $ImportedCSV[0].PSObject.Properties.Name
        foreach ($header in $requiredHeaders) {
            if ($header -notin $csvHeaders) {
                throw "Validation Failed: The CSV is missing the required header: '$header'."
            }
        }
        $usersToMigrate = New-Object System.Collections.ArrayList
        $computerName = hostname
        if ([string]::IsNullOrWhiteSpace($computerName)) {
            $computerName = $env:COMPUTERNAME
        }
        try {
            $serialNumber = (Get-WmiObject -Class Win32_BIOS).SerialNumber
        } catch {
            $serialNumber = (Get-CimInstance -Class Win32_BIOS).SerialNumber
        }
        $ValidDeviceRows = $ImportedCSV | Where-Object {
            ((-not [string]::IsNullOrWhiteSpace($_.JumpCloudUserName))) -and
            ($_.LocalComputerName -eq $computerName) -and
            ($_.SerialNumber -eq $serialNumber)
        }
        $duplicateSids = $ValidDeviceRows | Group-Object -Property 'SID' | Where-Object { $_.Count -gt 1 }
        if ($duplicateSids) {
            throw "Validation Failed: Duplicate SID '$($duplicateSids[0].Name)' found for LocalComputerName '$($computerName)'."
        }
        foreach ($row in $ValidDeviceRows) {
            if (($row.LocalComputerName -eq $computerName) -and ($row.SerialNumber -eq $serialNumber)) {
                if ($systemContextBinding -and [string]::IsNullOrWhiteSpace($row.JumpCloudUserID)) {
                    throw "VALIDATION FAILED: on row : 'JumpCloudUserID' cannot be empty when systemContextBinding is enabled. Halting script."
                }
                $requiredFields = "LocalPath", "SID"
                foreach ($field in $requiredFields) {
                    if ([string]::IsNullOrWhiteSpace($row.$field)) {
                        throw "Validation Failed: Required field '$field' is empty for user '$($row.JumpCloudUserName)'."
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
    }
    end {
        if ($usersToMigrate.Count -eq 0) {
            throw "Validation Failed: No users were found in the CSV matching this computer's configuration."
        }
        return $usersToMigrate
    }
}

function Get-MigrationUsersFromSystemDescription {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GetSystemScriptPath,
        [Parameter(Mandatory = $true)]
        [boolean]$systemContextBinding
    )
    begin {
        if (-not (Test-Path -Path $GetSystemScriptPath -PathType Leaf)) {
            throw "Validation Failed: Get-System script not found at: '$GetSystemScriptPath'."
        }
        # Dot source the Get-System function
        . $GetSystemScriptPath
    }
    process {
        try {
            Write-Host "[status] Retrieving system description from JumpCloud..."
            $systemDescription = Get-System -property "Description"
        } catch {
            throw "Failed to retrieve system description: $_"
        }

        # Validate that system description contains valid JSON
        if ([string]::IsNullOrEmpty($systemDescription)) {
            Write-Host "[status] System description is empty. No users to migrate."
            return $null
        }

        try {
            $users = $systemDescription | ConvertFrom-Json
        } catch {
            throw "Validation Failed: System description does not contain valid JSON: $_"
        }

        # Ensure we have an array
        if ($users.GetType().Name -eq 'PSCustomObject') {
            $users = @($users)
        }

        $usersToMigrate = New-Object System.Collections.ArrayList

        # Validate and process users from system description
        foreach ($user in $users) {
            # Validate required properties
            if ([string]::IsNullOrWhiteSpace($user.sid)) {
                Write-Host "[WARNING] Skipping user: Missing 'sid' property"
                continue
            }

            if ([string]::IsNullOrWhiteSpace($user.un)) {
                Write-Host "[WARNING] Skipping user: Missing 'un' (JumpCloud username) property"
                continue
            }

            # Skip users marked as 'Skip' or not in 'Pending' state
            if ($user.st -eq 'Skip') {
                Write-Host "[status] Skipping user marked as Skip: $($user.un)"
                continue
            }

            if ($user.st -ne 'Pending') {
                Write-Host "[status] Skipping user with status '$($user.st)': $($user.un)"
                continue
            }

            # For systemContextBinding, validate uid is present
            if ($systemContextBinding -and [string]::IsNullOrWhiteSpace($user.uid)) {
                throw "VALIDATION FAILED: User '$($user.un)' is missing 'uid' property required for systemContextBinding."
            }

            # Build user object for migration
            $migrationUser = [PSCustomObject]@{
                SelectedUsername  = $user.sid
                JumpCloudUserName = $user.un
                LocalPath         = $user.localPath
                JumpCloudUserID   = $user.uid
            }

            [void]$usersToMigrate.Add($migrationUser)
            Write-Host "[status] User queued for migration: $($user.un) (SID: $($user.sid))"
        }

        if ($usersToMigrate.Count -eq 0) {
            Write-Host "[status] No eligible users found in system description for migration."
            return $null
        }

        Write-Host "[status] $($usersToMigrate.Count) user(s) found and validated for migration."
        return $usersToMigrate
    }
}
function Get-LatestADMUGUIExe {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        # The full path to the discovery CSV file.
        [Parameter(Mandatory = $false)]
        [string]$destinationPath = "C:\Windows\Temp",
        # Optional GitHub token for authenticated requests (helps avoid rate limiting)
        [Parameter(Mandatory = $false)]
        [string]$GitHubToken,
        # Maximum number of retry attempts
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        # Delay between retries in seconds
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 20
    )

    begin {
        $owner = "TheJumpCloud"
        $repo = "jumpcloud-ADMU"
        $apiUrl = "https://api.github.com/repos/$owner/$repo/releases/latest"
        # Setup headers for authenticated requests if token is provided
        $headers = @{
            "Accept" = "application/vnd.github.v3+json"
        }
        if (-not [string]::IsNullOrEmpty($GitHubToken)) {
            $headers["Authorization"] = "Bearer $GitHubToken"
            Write-Host "Using authenticated GitHub API requests" -ForegroundColor Cyan
        }
    }
    process {
        $attempt = 0
        $success = $false
        $lastError = $null
        while ($attempt -lt $MaxRetries -and -not $success) {
            $attempt++
            try {
                if ($attempt -gt 1) {
                    Write-Host "Retry attempt $attempt of $MaxRetries..." -ForegroundColor Yellow
                }
                Write-Host "Querying GitHub API for the latest '$repo' release..." -ForegroundColor Yellow
                # Get latest release data from the GitHub API
                $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
                # Find the specific GUI executable asset
                $exeAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }
                if ($exeAsset) {
                    $downloadUrl = $exeAsset.browser_download_url
                    $fileName = $exeAsset.name
                    $fullPath = Join-Path -Path $destinationPath -ChildPath $fileName
                    Write-Host "Downloading '$fileName' (Version $($latestRelease.tag_name))..." -ForegroundColor Yellow
                    # Download with retry logic
                    $downloadAttempt = 0
                    $downloadSuccess = $false
                    while ($downloadAttempt -lt $MaxRetries -and -not $downloadSuccess) {
                        $downloadAttempt++
                        try {
                            Invoke-WebRequest -Uri $downloadUrl -OutFile $fullPath -ErrorAction Stop
                            $downloadSuccess = $true
                        } catch {
                            if ($downloadAttempt -lt $MaxRetries) {
                                Write-Host "Download failed. Retrying in $RetryDelaySeconds seconds..." -ForegroundColor Yellow
                                Start-Sleep -Seconds $RetryDelaySeconds
                            } else {
                                throw
                            }
                        }
                    }
                    Write-Host "Download complete! File saved to '$fullPath'." -ForegroundColor Green
                    $success = $true
                } else {
                    throw "Could not find 'gui_jcadmu.exe' in the latest release."
                }
            } catch {
                $lastError = $_
                $errorMessage = $_.Exception.Message
                $isRateLimit = $errorMessage -match "rate limit"
                $isNetworkError = $errorMessage -match "network|connection|timeout|unable to connect"
                if ($isRateLimit) {
                    Write-Host "GitHub API rate limit exceeded." -ForegroundColor Yellow
                    if ([string]::IsNullOrEmpty($GitHubToken)) {
                        Write-Host "Hint: Provide a GitHub token via -GitHubToken parameter for higher rate limits." -ForegroundColor Cyan
                    }
                } elseif ($isNetworkError) {
                    Write-Host "Network connectivity issue detected: $errorMessage" -ForegroundColor Yellow
                }
                if ($attempt -lt $MaxRetries) {
                    Write-Host "Waiting $RetryDelaySeconds seconds before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $RetryDelaySeconds
                } else {
                    $errorDetail = if ($lastError.ErrorDetails.Message) {
                        $lastError.ErrorDetails.Message
                    } else {
                        $lastError.Exception.Message
                    }
                    throw "Operation failed after $MaxRetries attempts. Last error: $errorDetail"
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
    return $argumentList
}
function Get-JcadmuGuiSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$GitHubToken,
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 5
    )
    begin {
        $apiUrl = "https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases"
        # Setup headers for authenticated requests if token is provided
        $headers = @{
            "Accept" = "application/vnd.github.v3+json"
        }
        if (-not [string]::IsNullOrEmpty($GitHubToken)) {
            $headers["Authorization"] = "Bearer $GitHubToken"
        }
    }
    process {
        $attempt = 0
        $success = $false
        $lastError = $null
        while ($attempt -lt $MaxRetries -and -not $success) {
            $attempt++
            try {
                if ($attempt -gt 1) {
                    Write-Host "Retry attempt $attempt of $MaxRetries for SHA256 retrieval..." -ForegroundColor Yellow
                }
                $releases = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -ErrorAction Stop
                if ($null -eq $releases -or $releases.Count -eq 0) {
                    throw "No releases were found for the repository."
                }
                $latestRelease = $releases[0]
                $latestTag = $latestRelease.tag_name
                # Find the specific asset within the 'assets' array
                $targetAsset = $latestRelease.assets | Where-Object { $_.name -eq 'gui_jcadmu.exe' }
                if ($targetAsset) {
                    $digest = $targetAsset.digest
                    if ($digest -and $digest.StartsWith('sha256:')) {
                        $sha256 = $digest.Split(':')[1]
                        $success = $true
                        return [PSCustomObject]@{
                            TagName = $latestTag
                            SHA256  = $sha256
                        }
                    } else {
                        throw "SHA256 digest not found or in unexpected format for 'gui_jcadmu.exe'."
                    }
                } else {
                    throw "Asset 'gui_jcadmu.exe' not found in the latest release (Tag: $latestTag)."
                }
            } catch {
                $lastError = $_
                $errorMessage = $_.Exception.Message
                # Check for specific error types
                $isRateLimit = $errorMessage -match "rate limit|403|forbidden"
                $isNetworkError = $errorMessage -match "network|connection|timeout|unable to connect"
                if ($isRateLimit) {
                    Write-Host "GitHub API access issue (rate limit or 403 Forbidden)." -ForegroundColor Yellow
                    if ([string]::IsNullOrEmpty($GitHubToken)) {
                        Write-Host "Hint: Provide a GitHub token via -GitHubToken parameter to avoid rate limiting." -ForegroundColor Cyan
                    }
                } elseif ($isNetworkError) {
                    Write-Host "Network connectivity issue detected: $errorMessage" -ForegroundColor Yellow
                }
                if ($attempt -lt $MaxRetries) {
                    Write-Host "Waiting $RetryDelaySeconds seconds before retry..." -ForegroundColor Yellow
                    Start-Sleep -Seconds $RetryDelaySeconds
                } else {
                    # Final attempt failed
                    $errorDetail = if ($lastError.ErrorDetails.Message) {
                        $lastError.ErrorDetails.Message
                    } else {
                        $lastError.Exception.Message
                    }
                    throw "An API error or network issue occurred after $MaxRetries attempts: $errorDetail"
                }
            }
        }
    }
}
function Test-ExeSHA {
    param (
        [Parameter(Mandatory = $true)]
        [string]$filePath,
        [Parameter(Mandatory = $false)]
        [string]$GitHubToken
    )
    process {
        if (-not (Test-Path -Path $filePath)) {
            throw "The gui_jcadmu.exe file was not found at: '$filePath'."
        }
        # Pass GitHub token to Get-JcadmuGuiSha256 if available
        if (-not [string]::IsNullOrEmpty($GitHubToken)) {
            $releaseSHA256 = Get-JcadmuGuiSha256 -GitHubToken $GitHubToken
        } else {
            $releaseSHA256 = Get-JcadmuGuiSha256
        }
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
function Invoke-UserMigrationBatch {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$UsersToMigrate,

        [Parameter(Mandatory = $true)]
        [hashtable]$MigrationConfig
    )
    # Initialize results tracking
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
    # Get the last user for domain leave logic
    $lastUser = $UsersToMigrate | Select-Object -Last 1
    # Process each user migration
    foreach ($user in $UsersToMigrate) {
        $userStartTime = Get-Date
        $isLastUser = ($user -eq $lastUser)
        # Determine domain leave parameter for this user
        $leaveDomainParam = if ($isLastUser -and $MigrationConfig.LeaveDomainAfterMigration) { $true } else { $false }
        $removeMDMParam = if ($isLastUser -and $MigrationConfig.RemoveMDM) { $true } else { $false }
        # Build migration parameters for this user
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
        # Handle optional JumpCloudOrgID parameter
        if (-not [string]::IsNullOrEmpty($MigrationConfig.JumpCloudOrgID)) {
            $migrationParams.Add('JumpCloudOrgID', $MigrationConfig.JumpCloudOrgID)
        }
        # Handle system context binding parameters
        if ($MigrationConfig.systemContextBinding -eq $true) {
            $migrationParams.Remove('AutoBindJCUser')
            $migrationParams.Remove('JumpCloudAPIKey')
            $migrationParams.Remove('JumpCloudOrgID')
            $migrationParams.Add('systemContextBinding', $true)
            $migrationParams.Add('JumpCloudUserID', $user.JumpCloudUserID)
        }
        # Get domain status before migration
        $domainStatus = Get-DomainStatus
        Write-Host "[status] Domain status before migration:"
        Write-Host "[status] Azure/EntraID status: $($domainStatus.AzureAD)"
        Write-Host "[status] Local domain status: $($domainStatus.LocalDomain)"
        Write-Host "[status] Begin Migration for JumpCloudUser: $($user.JumpCloudUserName)"
        # Execute the migration
        $migrationResult = Invoke-SingleUserMigration -User $user -MigrationParams $migrationParams -GuiJcadmuPath $MigrationConfig.guiJcadmuPath
        # Track results
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
            Write-Host "[status] Migration completed successfully for user: $($user.JumpCloudUserName)"
        } else {
            $results.FailedMigrations++
            $results.FailedUsers += $userResult
            Write-Host "[status] Migration failed for user: $($user.JumpCloudUserName)"
        }
    }
    $results.EndTime = Get-Date
    $results.Duration = $results.EndTime - $results.StartTime
    Write-Host "`nAll user migrations have been processed."
    return $results
}
function Invoke-SingleUserMigration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$User,

        [Parameter(Mandatory = $true)]
        [hashtable]$MigrationParams,

        [Parameter(Mandatory = $true)]
        [string]$GuiJcadmuPath
    )
    if (-not (Test-Path -Path $GuiJcadmuPath)) {
        throw "The gui_jcadmu.exe file was not found at: '$GuiJcadmuPath'. Please ensure the file is present before running the migration."
    }
    $convertedParams = ConvertTo-ArgumentList -InputHashtable $MigrationParams
    Write-Host "[status] Executing migration command..."
    # Execute the migration
    $result = & $GuiJcadmuPath $convertedParams
    # get the exit code
    $exitCode = $LASTEXITCODE
    Write-Host "[status] Migration process completed with exit code: $exitCode"
    Write-Host "`n[status] Migration output:"
    $result | Out-Host
    Write-Host "`n"
    if ($exitCode -eq 0) {
        # return true
        return [PSCustomObject]@{
            Success      = $true
            ErrorMessage = $null
        }
    } else {
        return [PSCustomObject]@{
            Success      = $false
            ErrorMessage = $result[-1]
        }
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
            if ($line -match "AzureADJoined : ") {
                $AzureADStatus = ($line.TrimStart('AzureADJoined : '))
            }
            if ($line -match "DomainJoined : ") {
                $LocalDomainStatus = ($line.TrimStart('DomainJoined : '))
            }
        }
        return [PSCustomObject]@{
            AzureAD     = $AzureADStatus
            LocalDomain = $LocalDomainStatus
        }
    } catch {
        Write-Host "[status] Error getting domain status: $($_.Exception.Message)"
        return [PSCustomObject]@{
            AzureAD     = "Error"
            LocalDomain = "Error"
        }
    }
}
#endregion functionDefinitions

#region validation
# validate migration parameters
$confirmMigrationParameters = Confirm-MigrationParameter `
    -dataSource $dataSource `
    -csvName $csvName `
    -TempPassword $TempPassword `
    -LeaveDomain $LeaveDomain `
    -ForceReboot $ForceReboot `
    -UpdateHomePath $UpdateHomePath `
    -AutoBindJCUser $AutoBindJCUser `
    -PrimaryUser $PrimaryUser `
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
if ($dataSource -eq 'CSV') {
    Write-Host "[status] Using CSV source for migration users..."
    if (-not $csvName) {
        Write-Host "[status] Required script variable 'csvName' not set, exiting..."
        exit 1
    }
} elseif ($dataSource -eq 'Description') {
    Write-Host "[status] Using system description source for migration users..."
    Write-Host "[status] Importing Get-System function for system description retrieval..."
}

# Call the unified function and store the result (which is either an array of users or $null)
try {
    $UsersToMigrate = Get-MigrationUsers -source $dataSource -csvName $csvName -systemContextBinding $systemContextBinding
} catch {
    Write-Host "[ERROR] Failed to retrieve migration users: $_"
    exit 1
}
#endregion dataImport

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
    Write-Host "[status] Logging off users..."
    foreach ($user in $UsersList) {
        if (($user.username)) {
            Write-Host "[status] Logging off user: $($user.username) with ID: $($user.ID)"
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
Get-LatestADMUGUIExe
# Validate the downloaded file against the official release hash
Test-ExeSHA -filePath $guiJcadmuPath
# Execute the migration batch processing
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
# Display results summary
Write-Host "`nMigration Results Summary:"
Write-Host "Total Users Processed: $($migrationResults.TotalUsers)"
Write-Host "Successful Migrations: $($migrationResults.SuccessfulMigrations)"
Write-Host "Failed Migrations: $($migrationResults.FailedMigrations)"
if ($migrationResults.FailedUsers.Count -gt 0) {
    Write-Host "`nFailed Users:"
    foreach ($failedUser in $migrationResults.FailedUsers) {
        Write-Host "  - $($failedUser.JumpCloudUserName)"
    }
    exit 1
} else {
    # process remainder of the script:
    #region restart/shutdown
    # If force restart was specified, we kick off a command to initiate the restart
    # this ensures that the JumpCloud commands reports a success
    if ($ForceRebootAfterMigration) {
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
    }
    #endregion restart/shutdown
}
#endregion migration
exit 0