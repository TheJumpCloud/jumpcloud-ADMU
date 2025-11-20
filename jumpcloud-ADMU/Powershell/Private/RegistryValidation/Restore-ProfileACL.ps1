function Restore-ProfileACL {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    process {
        # Define the target directory for the restore
        $targetPath = "C:\Users\"
        $logStep = "Restore-ProfileACL" # Define step name once
        $ACLRestoreLogPath = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu_ACL_Restore.log"

        Write-ToLog -Message "Starting Permission Restore." -Level Info -Step $logStep

        # 1. Validate the Backup Path
        if (-not (Test-Path -Path $BackupPath -PathType Leaf)) {
            Write-ToLog -Message "The specified backup file was not found: '$BackupPath'. Aborting restore." -Level Error -Step $logStep
            # Use Write-Error for standard PowerShell error handling
            Write-ToLog -Message "The specified backup file was not found: '$BackupPath'. Aborting restore." -Level Error -Step $logStep
            return
        }

        # 2. Validate the Target Path
        if (-not (Test-Path -Path $targetPath -PathType Container)) {
            Write-ToLog -Message "The target directory was not found: '$targetPath'. Aborting restore." -Level Warning -Step $logStep
            return
        }

        Write-ToLog -Message "Restore file path validated: '$BackupPath'" -Level Info -Step $logStep
        Write-ToLog -Message "Target directory validated: '$targetPath'" -Level Info -Step $logStep
        Write-ToLog -Message "Running icacls restore command..." -Level Info -Step $logStep

        # 3. Execute the icacls Restore Command
        try {
            # Restore and only get this output: Successfully processed 7962 files; Failed processing 0 files
            $restoreResult = icacls $targetPath /restore $BackupPath /T /C > $ACLRestoreLogPath 2>&1
            if ($LASTEXITCODE -ne 0) {
                # Only log if there are non-filtered errors
                Write-ToLog "Warning: icacls save operation had issues. Exit code: $LASTEXITCODE" -Level Verbose -Step $logStep
            } else {
                Write-ToLog "Restore operation completed." -Level Verbose -Step $logStep
            }
        } catch {
            Write-ToLog -Message "An error occurred during the icacls execution: $($_.Exception.Message)" -Level Warning -Step $logStep
        }
    }

}