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
        $ACLPermissionLogPath = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu_ACL.log"
    }
    process {
        # Test if the directory exists. If not, create it recursively.
        if (-Not (Test-Path -Path $path)) {
            Write-ToLog "Creating directory: `"$path`"" -Level "Verbose"
            New-Item -ItemType Directory -Force -Path $path | Out-Null
        }

        Write-ToLog "Backup file will be saved as: `"$file`"" -Level "Verbose"
        Write-ToLog "Running ICACLS to save permissions. This may take a moment..." -Level "Verbose"

        $aclResults = icacls $ProfileImagePath /save $file /T /C > $ACLPermissionLogPath 2>&1

        if ($LASTEXITCODE -ne 0) {
            # Only log if there are non-filtered errors
            Write-ToLog "Warning: icacls save operation had issues. Exit code: $LASTEXITCODE" -Level Verbose
        } else {
            Write-ToLog "Permissions for '$ProfileImagePath' have been saved to '$file'."
        }
    }
}
