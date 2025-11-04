function Backup-ProfileImageACL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Full path to the user profile image folder.")]
        [string]$ProfileImagePath,
        [Parameter(Mandatory = $true, HelpMessage = "SID of the user.")]
        [string]$sourceSID
    )

    try {
        # No need to validate ProfileImagePath since it's validated prior to function execution
        $timestamp = Get-Date -Format "yyyyMMdd-HHmm"
        $backupFileName = "${sourceSID}_permission_backup_${timestamp}"

        # Define the full directory path for the backup file
        $backupDirectory = Join-Path -Path $ProfileImagePath -ChildPath "AppData\Local\JumpCloudADMU"

        if (-not (Test-Path -Path $backupDirectory -PathType Container)) {
            Write-ToLog "Creating backup directory: '$backupDirectory'"
            try {
                New-Item -Path $backupDirectory -ItemType Directory | Out-Null
            } catch {
                Write-ToLog "Failed to create backup directory: '$backupDirectory'. Error: $($_.Exception.Message)" -Level Error
                # Prevent further execution if directory creation fails
                return
            }

        }
        # Define the full backup file path
        $backupFilePath = Join-Path -Path $backupDirectory -ChildPath $backupFileName


        Write-ToLog "Backup file will be saved as: `"$backupFilePath`""
        Write-ToLog "Running ICACLS to save permissions. This may take a moment..."

        $Output = icacls "$ProfileImagePath" /save "$backupFilePath" /T /C 2>&1
        $Summary = $Output | Select-Object -Last 1

        Write-ToLog $Summary

        if ($LASTEXITCODE -eq 0) {
            Write-ToLog "Permissions for '$ProfileImagePath' have been saved to '$backupFilePath'."
        }
    } catch {
        # Catch errors from the ValidateScript block or other unexpected issues
        Write-ToLog "An unexpected error occurred: $($_.Exception.Message)" -Level Error
    }
}