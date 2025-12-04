function Restore-ProfileACL {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )
    process {
        # Define the target directory for the restore
        $targetPath = "C:\Users\"
        $logStep = "Restore-ProfileACL" # Define step name once

        Write-ToLog -Message "Starting Permission Restore." -Level Info -Step $logStep

        # 1. Validate the Backup Path
        if (-not (Test-Path -Path $BackupPath -PathType Leaf)) {
            Write-ToLog -Message "The specified backup file was not found: '$BackupPath'. Aborting restore." -Level Error -Step $logStep
            # Use Write-Error for standard PowerShell error handling
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
            # Restore
            Write-ToLog -Message "================ ACL Restore Log ================" -Level Info -Step $logStep
            # Save and append the log to \Windows\Temp\jcAdmu.log
            $logPath = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log"
            $restoreResult = icacls $targetPath /restore $BackupPath /T /C /Q 2>&1
            # Save icacls output to log file
            $restoreResult | Out-File -FilePath $logPath -Append -Encoding utf8
            Write-ToLog -Message "================ End of ACL Restore Log ================" -Level Info -Step $logStep

            if ($LASTEXITCODE -ne 0) {
                # Only log if there are non-filtered errors
                Write-ToLog "Warning: icacls save operation had issues. Exit code: $LASTEXITCODE" -Level Verbose -Step $logStep
            } else {
                Write-ToLog "Restore ACL operation completed." -Level Verbose -Step $logStep
            }
        } catch {
            Write-ToLog -Message "An error occurred during the icacls execution: $($_.Exception.Message)" -Level Warning -Step $logStep
        }
    }

}