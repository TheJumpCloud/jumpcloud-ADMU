# Function to write progress to the progress bar or console
function Write-ToProgress {
    param (
        [Parameter(Mandatory = $false)]
        $form,
        [Parameter(Mandatory = $false)]
        $progressBar,
        [Parameter(Mandatory = $true)]
        $status,
        [Parameter(Mandatory = $false)]
        $logLevel,
        [Parameter(Mandatory = $false)]
        $username,
        [Parameter(Mandatory = $false)]
        $newLocalUsername,
        [Parameter(Mandatory = $false)]
        $profileSize,
        [Parameter(Mandatory = $false)]
        $LocalPath

    )
    # Create a hashtable of all status messages
    $statusMessages = [ordered]@{
        "Init"                    = "Initializing Migration"
        "Install"                 = "Installing JumpCloud Agent"
        "BackupUserFiles"         = "Backing up user profile"
        "UserProfileUnit"         = "Initializing new user profile"
        "BackupRegHive"           = "Backing up registry hive"
        "VerifyRegHive"           = "Verifying registry hive"
        "CopyLocalReg"            = "Copying local user registry"
        "GetACL"                  = "Getting ACLs"
        "CopyUser"                = "Copying selected user to new user"
        "CopyUserRegFiles"        = "Copying user registry files"
        "CopyMergedProfile"       = "Copying merged profiles to destination profile path"
        "CopyDefaultProtocols"    = "Copying default protocol associations"
        "ValidateUserPermissions" = "Validating user permissions"
        "CreateRegEntries"        = "Creating registry entries"
        "DownloadUWPApps"         = "Downloading UWP Apps"
        "CheckADStatus"           = "Checking AD Status"
        "ConversionComplete"      = "Profile conversion complete"
        "MigrationComplete"       = "Migration completed successfully"
    }
    # If status is error message, write to log
    if ($logLevel -eq "Error") {
        $statusMessage = $Status
        $PercentComplete = 100
    } else {
        # Get the status message
        $statusMessage = $statusMessages[$status]
        # Count the number of status messages
        $statusCount = $statusMessages.Count
        # Get the index of the status message using for loop
        $statusIndex = [array]::IndexOf($statusMessages.Keys, $status)
        # Calculate the percentage complete based on the index of the status message
        $PercentComplete = ($statusIndex / ($statusCount - 1)) * 100
    }
    if ($form) {
        if ($username -or $newLocalUsername -or $profileSize -or $LocalPath) {
            # Pass in the migration details to the progress bar
            Update-ProgressForm -progressBar $progressBar -percentComplete $PercentComplete -Status $statusMessage -username $username -newLocalUsername $newLocalUsername -profileSize $profileSize -localPath $LocalPath
        } else {
            Update-ProgressForm -progressBar $progressBar -percentComplete $PercentComplete -Status $statusMessage -logLevel $logLevel
        }
    } else {
        Write-Progress -Activity "Migration Progress" -percentComplete $percentComplete -status $statusMessage
    }
}