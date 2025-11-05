function Backup-ProfileImageACL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Full path to the user profile image folder.")]
        [string]$ProfileImagePath,
        [Parameter(Mandatory = $true, HelpMessage = "SID of the user.")]
        [string]$sourceSID
    )
    begin {
        $timestamp = Get-Date -Format "yyyyMMdd-HHmm"
        $path = "$ProfileImagePath\AppData\Local\JumpCloudADMU"
        $file = "$path\${sourceSID}_permission_backup_${timestamp}"
    }
    process {
        try {

            # Test if the directory exists. If not, create it recursively.
            if (!(Test-Path -Path $path -PathType Container)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            Write-ToLog "Backup file will be saved as: `"$file`""
            Write-ToLog "Running ICACLS to save permissions. This may take a moment..."

            $Output = icacls $ProfileImagePath /save $file /T /C 2>&1
            $Summary = $Output | Select-Object -Last 1

            Write-ToLog $Summary

            if ($LASTEXITCODE -eq 0) {
                Write-ToLog "Permissions for '$ProfileImagePath' have been saved to '$file'."
            }
        } catch {
            # Catch errors from the ValidateScript block or other unexpected issues
            Write-ToLog "An unexpected error occurred: $($_.Exception.Message)" -Level Error
        }
    }
}