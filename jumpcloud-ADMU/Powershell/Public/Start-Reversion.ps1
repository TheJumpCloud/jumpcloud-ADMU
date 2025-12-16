Function Start-Reversion {
    <#
    .SYNOPSIS
        Reverts a user migration by restoring original registry files for a specified Windows SID.

    .DESCRIPTION
        This function reverts a user migration by:
        1. Looking up the account SID in the Windows registry ProfileList
        2. Identifying the .ADMU profile path
        3. Restoring original NTUSER.DAT and UsrClass.dat files from backups
        4. Preserving migrated files with _migrated suffix for rollback purposes

    .PARAMETER UserSID
        The Windows Security Identifier (SID) of the user account to revert.

    .PARAMETER TargetProfileImagePath
        The actual profile path to revert. If not specified, will use the path from the registry.
        This path will be validated to ensure it exists and is associated with the UserSID.

    .PARAMETER DryRun
        Shows what actions would be performed without actually executing them.

    .PARAMETER Force
        Bypasses confirmation prompts and forces the revert operation.

    .EXAMPLE
        Start-Reversion -UserSID "S-1-5-21-123456789-1234567890-123456789-1001"
        Reverts the migration for the specified user SID using the registry profile path.

    .EXAMPLE
        Start-Reversion -UserSID "S-1-5-21-123456789-1234567890-123456789-1001" -TargetProfileImagePath "C:\Users\john.doe"
        Reverts the migration using a specific target profile path instead of the registry value.

    .EXAMPLE
        Start-Reversion -UserSID "S-1-5-21-123456789-1234567890-123456789-1001" -DryRun
        Shows what would be reverted without making actual changes.

    .OUTPUTS
        [PSCustomObject] Returns revert operation results with success status and details.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [string]$UserSID,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateScript({
                if (Test-Path $_ -PathType Container) { $true }
                else { throw "Target profile path does not exist: $_" }
            })]
        [string]$TargetProfileImagePath,
        [Parameter(Mandatory = $false)]
        [bool]$form = $false,
        [Parameter(Mandatory = $false)]
        [string]$UserName,
        [Parameter(Mandatory = $false)]
        [string]$ProfileSize,
        [Parameter(Mandatory = $false)]
        [string]$LocalPath,
        [Parameter(Mandatory = $false)]
        [switch]$DryRun,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    Begin {
        Write-ToLog -Message "Begin Revert Migration" -MigrationStep -Level Info

        # Initialize result object
        $revertResult = [PSCustomObject]@{
            Success             = $false
            UserSID             = $UserSID
            RegistryProfilePath = $null
            TargetProfilePath   = $TargetProfileImagePath
            ActualProfilePath   = $null
            FilesReverted       = @()
            Errors              = @()
            StartTime           = Get-Date
            EndTime             = $null
            WhatIfMode          = $DryRun.IsPresent
            RegistryUpdated     = $false
        }
        $account = New-Object System.Security.Principal.SecurityIdentifier($UserSID)
        $domainUser = ($account.Translate([System.Security.Principal.NTAccount])).Value

        # Regex pattern to identify .ADMU profile paths
        $admuPathPattern = '\.ADMU$'

        Write-ToLog -Message "Validating user SID: $UserSID" -Level Verbose -Step "Revert-Migration"
        if ($form) {
            $script:ProgressBar = New-ProgressForm
            $StatusType = "Reversion"
        }
    }

    Process {
        try {
            #region Validate Registry and Determine Profile Path
            Write-ToLog -Message "Looking up profile information for SID: $UserSID" -Level Info -Step "Revert-Migration"
            Write-ToProgress -form $form -Status "RevertInit" -ProgressBar $ProgressBar -StatusType $StatusType -Username $UserName -ProfileSize $ProfileSize -LocalPath $LocalPath

            # Get profile information from registry for validation
            $profileRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID"

            Write-ToProgress -form $form -Status "RevertValidateProfilePath" -ProgressBar $ProgressBar -StatusType $StatusType
            if (-not (Test-Path $profileRegistryPath)) {
                throw "Profile registry path not found for SID: $UserSID"
            }

            $registryProfileImagePath = (Get-ItemProperty -Path $profileRegistryPath -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath
            $revertResult.RegistryProfilePath = $registryProfileImagePath

            Write-ToLog -Message "Found registry profile path: $registryProfileImagePath" -Level Info -Step "Revert-Migration"

            # Validate this is an ADMU migrated profile by checking registry path
            if ($registryProfileImagePath -notmatch $admuPathPattern) {
                throw "Registry profile path does not contain .ADMU suffix. This does not appear to be a migrated profile: $registryProfileImagePath"
            }

            Write-ToLog -Message "Confirmed .ADMU migration profile detected in registry" -Level Verbose -Step "Revert-Migration"

            # Determine which profile path to use
            if ($TargetProfileImagePath) {
                Write-ToLog -Message "Using provided target profile path: $TargetProfileImagePath" -Level Info -Step "Revert-Migration"
                $profileImagePath = $TargetProfileImagePath

                # Validate target profile path is associated with the UserSID
                $sidValidation = Confirm-ProfileSidAssociation -ProfilePath $TargetProfileImagePath -UserSID $UserSID
                if (-not $sidValidation.IsValid) {
                    throw "Target profile path validation failed: $($sidValidation.Reason)"
                }
                Write-ToLog -Message "Target profile path validated for UserSID: $UserSID" -Level Verbose -Step "Revert-Migration"
            } else {
                # Use registry path, remove .ADMU suffix
                $profileImagePath = $registryProfileImagePath -replace $admuPathPattern, ''
                $sidValidation = Confirm-ProfileSidAssociation -ProfilePath $profileImagePath -UserSID $UserSID
                if (-not $sidValidation.IsValid) {
                    throw "Registry profile path validation failed: $($sidValidation.Reason)"
                }
                Write-ToLog -Message "Using registry profile path (without .ADMU): $profileImagePath" -Level Info -Step "Revert-Migration"
            }

            $revertResult.ActualProfilePath = $profileImagePath
            #endregion Validate Registry and Determine Profile Path

            #region Validate Profile Directory
            if (-not (Test-Path $profileImagePath -PathType Container)) {
                throw "Profile directory does not exist: $profileImagePath"
            }

            Write-ToLog -Message "Profile directory exists and is accessible" -Level Verbose -Step "Revert-Migration"
            Write-ToLog -Message "Profile path: $profileImagePath" -Level Verbose -Step "Revert-Migration"
            #endregion Validate Profile Directory

            #region Validate ProfileImagePath ACL Backup in $profileImagePath\AppData\Local\JumpCloudADMU
            Write-ToProgress -form $form -Status "RevertValidateACLBackups" -ProgressBar $ProgressBar -StatusType $StatusType
            # Regex pattern to identify ACL backup files: S-1-12-1-3466645622-1152519358-2404555438-459629385_permission_backup_20251117-1353
            $aclBackupPattern = "^{0}_permission_backup_\d{{8}}-\d{{4}}$" -f [Regex]::Escape($UserSID)
            $aclBackupDir = Join-Path -Path $profileImagePath -ChildPath "AppData\Local\JumpCloudADMU"
            $aclBackupFiles = @()
            if (Test-Path -Path $aclBackupDir -PathType Container) {
                $aclBackupFiles = Get-ChildItem -Path $aclBackupDir -File | Where-Object { $_.Name -match $aclBackupPattern }
            }
            $latestAclBackupFile = $aclBackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            # Get the most recent ACL backup file path

            if ($aclBackupFiles.Count -eq 0) {
                Throw "No ACL backup files found in directory: $aclBackupDir for SID: $UserSID. Cannot proceed with revert."
            } else {
                Write-ToLog -Message "Found ACL backup files in $aclBackupDir" -Level Info -Step "Revert-Migration"
            }
            #endregion Validate ProfileImagePath ACL Backup

            #region Identify Registry Files to Revert
            $registryFiles = @()

            # NTUSER.DAT files in profile root
            $ntuserCurrent = Join-Path $profileImagePath "NTUSER.DAT"
            $ntuserOriginalFiles = Get-ChildItem -Path $profileImagePath -Force | Where-Object { $_.Name -match "NTUSER_original_*" }

            if ($ntuserOriginalFiles.Count -eq 0) {
                Write-ToLog -Message "Warning: No original NTUSER.DAT backup found in $profileImagePath" -Level Warning -Step "Revert-Migration"
            } else {
                $ntuserOriginal = $ntuserOriginalFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $ntuserMigrated = $ntuserCurrent -replace '\.DAT$', '_migrated.DAT'

                $registryFiles += [PSCustomObject]@{
                    Type         = "NTUSER"
                    CurrentFile  = $ntuserCurrent
                    OriginalFile = $ntuserOriginal.FullName
                    MigratedFile = $ntuserMigrated
                    Location     = "Profile Root"

                }

                Write-ToLog -Message "Found NTUSER original backup: $($ntuserOriginal.Name)" -Level Info -Step "Revert-Migration"
            }
            # Validate that the UsrClass and NTUSER original files were found
            if ($registryFiles.Type -notcontains "NTUSER") {
                Throw "No NTUser.DAT backup files found in directory: $profileImagePath for SID: $UserSID. Cannot proceed with revert."
            }

            # UsrClass.dat files in AppData
            $appDataPath = Join-Path $profileImagePath "AppData\Local\Microsoft\Windows"
            $usrClassCurrent = Join-Path $appDataPath "UsrClass.dat"
            $usrClassOriginalPattern = Join-Path $appDataPath "UsrClass_original_*.dat"
            $usrClassOriginalFiles = Get-ChildItem -Path $usrClassOriginalPattern -Force | Where-Object { $_.Name -match "UsrClass_original_*" }

            if ($usrClassOriginalFiles.Count -eq 0) {
                Write-ToLog -Message "Warning: No original UsrClass.dat backup found in $appDataPath" -Level Warning -Step "Revert-Migration"
            } else {
                $usrClassOriginal = $usrClassOriginalFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                $usrClassMigrated = $usrClassCurrent -replace '\.dat$', '_migrated.dat'

                $registryFiles += [PSCustomObject]@{
                    Type         = "UsrClass"
                    CurrentFile  = $usrClassCurrent
                    OriginalFile = $usrClassOriginal.FullName
                    MigratedFile = $usrClassMigrated
                    Location     = "AppData"
                }

                Write-ToLog -Message "Found UsrClass original backup: $($usrClassOriginal.Name)" -Level Info -Step "Revert-Migration"
            }

            if ($registryFiles.Type -notcontains "UsrClass") {
                Throw "No UsrClass.dat backup files found in directory: $profileImagePath for SID: $UserSID. Cannot proceed with revert."
            }
            #endregion Identify Registry Files to Revert

            #region Validate Files Before Revert
            Write-ToProgress -form $form -Status "RevertValidateRegistryFiles" -ProgressBar $ProgressBar -StatusType $StatusType
            Write-ToLog -Message "Validating registry files before revert operation" -Level Info -Step "Revert-Migration"

            foreach ($regFile in $registryFiles) {
                # Check if original backup exists
                if (-not (Test-Path $regFile.OriginalFile)) {
                    throw "Original backup file not found: $($regFile.OriginalFile)"
                }

                # Check if current file exists
                if (-not (Test-Path $regFile.CurrentFile)) {
                    Write-ToLog -Message "Warning: Current $($regFile.Type) file not found: $($regFile.CurrentFile)" -Level Warning -Step "Revert-Migration"
                }

                Write-ToLog -Message "Validated $($regFile.Type) files in $($regFile.Location)" -Level Verbose -Step "Revert-Migration"
            }
            #endregion Validate Files Before Revert

            #region Confirmation Prompt
            if (-not $Force -and -not $DryRun) {
                Write-ToLog -Message "Requesting user confirmation for revert operation" -Level Info -Step "Revert-Migration"

                Write-Host "`nADMU Migration Revert Summary:" -ForegroundColor Yellow
                Write-Host "  User SID: $UserSID" -ForegroundColor White
                Write-Host "  Registry Profile Path: $registryProfileImagePath" -ForegroundColor White
                Write-Host "  Target Profile Path: $profileImagePath" -ForegroundColor White
                Write-Host "  Registry Files to Revert: $($registryFiles.Count)" -ForegroundColor White

                foreach ($regFile in $registryFiles) {
                    Write-Host "    - $($regFile.Type) ($($regFile.Location))" -ForegroundColor Gray
                    Write-Host "        Current:  $($regFile.CurrentFile)" -ForegroundColor DarkGray
                    Write-Host "        Backup: $($regFile.OriginalFile)" -ForegroundColor DarkGray
                }
                Write-Host "`nWARNING: This operation will overwrite the current registry files with the original backups and change the ownership of the profile directory to $domainUser." -ForegroundColor Red
                $confirmation = Read-Host "`nDo you want to proceed with the revert? (y/N)"
                if ($confirmation -notmatch '^[Yy]([Ee][Ss])?$') {
                    Write-ToLog -Message "Revert operation cancelled by user" -Level Info -Step "Revert-Migration"
                    $revertResult.Errors += "Operation cancelled by user"
                    return $revertResult
                }
            }
            #endregion Confirmation Prompt

            #region Perform Registry File Revert
            Write-ToProgress -form $form -Status "RevertRegistryFiles" -ProgressBar $ProgressBar -StatusType $StatusType
            Write-ToLog -Message "Beginning registry file revert operations" -Level Info -Step "Revert-Migration"

            foreach ($regFile in $registryFiles) {
                try {
                    Write-ToLog -Message "Processing $($regFile.Type) files in $($regFile.Location)" -Level Info -Step "Revert-Migration"

                    if ($DryRun) {
                        Write-Host "WHAT IF: Would rename $($regFile.CurrentFile) to $($regFile.MigratedFile)" -ForegroundColor Cyan
                        Write-Host "WHAT IF: Would rename $($regFile.OriginalFile) to $($regFile.CurrentFile)" -ForegroundColor Cyan
                    } else {
                        # Step 1: Rename current file to _migrated (preserve migration state)
                        if (Test-Path $regFile.CurrentFile) {
                            Write-ToLog -Message "Renaming current $($regFile.Type) to migrated backup: $($regFile.MigratedFile)" -Level Verbose -Step "Revert-Migration"
                            Move-Item -Path $regFile.CurrentFile -Destination $regFile.MigratedFile -Force
                        }

                        # Step 2: Rename original backup to current (restore original state)
                        Write-ToLog -Message "Restoring original $($regFile.Type) file: $($regFile.CurrentFile)" -Level Verbose -Step "Revert-Migration"
                        Move-Item -Path $regFile.OriginalFile -Destination $regFile.CurrentFile -Force

                        # Verify the restore was successful
                        if (Test-Path $regFile.CurrentFile) {
                            $revertResult.FilesReverted += $regFile
                            Write-ToLog -Message "Successfully reverted $($regFile.Type) in $($regFile.Location)" -Level Info -Step "Revert-Migration"
                        } else {
                            throw "Failed to restore $($regFile.Type) file to $($regFile.CurrentFile)"
                        }
                    }

                } catch {
                    $errorMsg = "Failed to revert $($regFile.Type) files: $($_.Exception.Message)"
                    Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
                    $revertResult.Errors += $errorMsg
                }
            }
            #endregion Perform Registry File Revert

            #region Update Registry ProfileImagePath
            Write-ToProgress -form $form -Status "RevertProfileImagePath" -ProgressBar $ProgressBar -StatusType $StatusType
            Write-ToLog -Message "Updating registry ProfileImagePath to point to reverted profile location" -Level Info -Step "Revert-Migration"

            try {
                if ($DryRun) {
                    Write-ToLog "WHAT IF: Would update registry ProfileImagePath from '$registryProfileImagePath' to '$profileImagePath'" -Level Verbose -Step "Revert-Migration"
                } else {
                    # Update the ProfileImagePath in the registry to point to the target profile path
                    # This informs Windows where to find the restored .DAT files
                    Write-ToLog -Message "Updating ProfileImagePath from '$registryProfileImagePath' to '$profileImagePath'" -Level Verbose -Step "Revert-Migration"

                    Set-ItemProperty -Path $profileRegistryPath -Name "ProfileImagePath" -Value $profileImagePath -Force

                    # Verify the update was successful
                    $updatedPath = (Get-ItemProperty -Path $profileRegistryPath -Name "ProfileImagePath").ProfileImagePath
                    if ($updatedPath -eq $profileImagePath) {
                        Write-ToLog -Message "Successfully updated registry ProfileImagePath to: $profileImagePath" -Level Info -Step "Revert-Migration"
                        $revertResult.RegistryUpdated = $true
                    } else {
                        throw "Registry update verification failed. Expected: '$profileImagePath', Got: '$updatedPath'"
                    }
                }
            } catch {
                $errorMsg = "Failed to update registry ProfileImagePath: $($_.Exception.Message)"
                Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
                $revertResult.Errors += $errorMsg
                $revertResult.RegistryUpdated = $false
            }
            #endregion Update Registry ProfileImagePath

            #region Restore Profile ACLs
            if (-not $DryRun) {
                Write-ToProgress -form $form -Status "RevertProfileACLs" -ProgressBar $ProgressBar -StatusType $StatusType
                Write-ToLog -Message "Restoring profile ACLs from backup" -Level Info -Step "Revert-Migration"
                try {
                    if ($latestAclBackupFile) {
                        $backupPath = Join-Path -Path $aclBackupDir -ChildPath $latestAclBackupFile.Name
                        Restore-ProfileACL -BackupPath $backupPath
                        Write-ToLog -Message "Successfully restored profile ACLs from: $($latestAclBackupFile.Name)" -Level Info -Step "Revert-Migration"
                    } else {
                        Write-ToLog -Message "No ACL backup file found to restore permissions." -Level Warning -Step "Revert-Migration"
                    }
                } catch {
                    $errorMsg = "Failed to restore profile ACLs: $($_.Exception.Message)"
                    Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
                    $revertResult.Errors += $errorMsg
                }
            } else {
                Write-ToLog -Message "WHAT IF: Would restore profile ACLs from backup file: $($latestAclBackupFile.Name)" -Level Verbose -Step "Revert-Migration"
            }
            #endregion Restore Profile ACLs

            #region Take Ownership of Profile Directory
            if (-not $DryRun) {
                Write-ToProgress -form $form -Status "RevertTakeOwnership" -ProgressBar $ProgressBar -StatusType $StatusType
                Write-ToLog -Message "Setting ownership of profile directory: $profileImagePath" -Level Verbose -Step "Revert-Migration"

                $ACLRestoreLogPath = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu_Revert_SetOwner.log"
                $logPath = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log"
                $icaclsOwnerResult = icacls "$($profileImagePath)" /setowner $domainUser /T /C /Q 2>&1
                $icaclsOwnerResult | Out-File -FilePath $logPath -Append -Encoding utf8

                Write-ToLog -Message "End of Set Owner Log" -Level Info -Step "Revert-Migration"

                # Check if any error occurred
                if ($LASTEXITCODE -ne 0) {
                    Write-ToLog -Message "Failed to set ownership of profile directory. Check log at $ACLRestoreLogPath" -Level Warning -Step "Revert-Migration"
                } else {
                    Write-ToLog -Message "Successfully set ownership of profile directory to $domainUser" -Level Info -Step "Revert-Migration"
                }
            } else {
                Write-ToLog -Message "WHAT IF: Would take ownership of profile directory: $profileImagePath" -Level Verbose -Step "Revert-Migration"
            }
            #endregion Take Ownership of Profile Directory

            #region Remove JumpCloud ADMU Created User
            $jcUsers = Get-LocalUser | Where-Object { $_.Description -eq 'Created by JumpCloud ADMU' }
            if (-not $DryRun) {
                # Check if the user have the $profileImagePath as profile path
                foreach ($jcUser in $jcUsers) {
                    #Get the profile path of the user
                    $jcUserProfilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($jcUser.SID.Value)" -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath
                    # Compare the profile path with the $profileImagePath
                    if ($jcUserProfilePath -eq $profileImagePath) {
                        Write-ToLog -message "Removing JumpCloud created user: $($jcUser.Name)" -Level Info -Step "Revert-Migration"
                        Write-ToProgress -form $form -Status "RevertRemoveJCUserArtifacts" -ProgressBar $ProgressBar -StatusType $StatusType
                        Remove-LocalUser -Name $jcUser.Name -ErrorAction Stop
                        Write-ToLog -message "Successfully removed JumpCloud created user: $($jcUser.Name)" -Level Info -Step "Revert-Migration"
                        # Remove it from the Registry
                        $jcUserRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($jcUser.SID.Value)"
                        if (Test-Path $jcUserRegPath) {
                            try {
                                Remove-Item -Path $jcUserRegPath -Recurse -Force -ErrorAction Stop
                                Write-ToLog -message "Successfully removed JumpCloud created user registry entry for SID: $($jcUser.SID.Value)" -Level Info -Step "Revert-Migration"
                            } catch {
                                $errorMsg = "Failed to remove JumpCloud created user registry entry for SID: $($jcUser.SID.Value): $($_.Exception.Message)"
                                Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
                                $revertResult.Errors += $errorMsg
                            }
                        } else {
                            Write-ToLog -message "No registry entry found for JumpCloud created user SID: $($jcUser.SID.Value)" -Level Warning -Step "Revert-Migration"
                        }
                    }
                }
            } else {
                Write-ToLog -Message "WHAT IF: Would check for JumpCloud created users to remove" -Level Verbose -Step "Revert-Migration"
                foreach ($jcUser in $jcUsers) {
                    #Get the profile path of the user
                    $jcUserProfilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($jcUser.SID.Value)" -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath
                    # Compare the profile path with the $profileImagePath
                    if ($jcUserProfilePath -eq $profileImagePath) {
                        Write-ToLog -message "WHAT IF: Would remove JumpCloud created user: $($jcUser.Name)" -Level Verbose -Step "Revert-Migration"
                    }
                }
            }
            #endregion Remove JumpCloud ADMU Created User

            #region Final Validation
            if (-not $DryRun) {
                Write-ToLog -Message "Performing post-revert validation" -Level Info -Step "Revert-Migration"

                $revertedCount = $revertResult.FilesReverted.Count
                $totalFiles = $registryFiles.Count
                $registryUpdated = $revertResult.RegistryUpdated

                if ($revertedCount -eq $totalFiles -and $registryUpdated) {
                    $revertResult.Success = $true
                    Write-ToLog -Message "Migration revert completed successfully. $revertedCount of $totalFiles registry files reverted and registry ProfileImagePath updated." -Level Info -Step "Revert-Migration"
                    Write-ToProgress -form $form -Status "RevertComplete" -ProgressBar $ProgressBar -StatusType $StatusType
                } elseif ($revertedCount -eq $totalFiles -and -not $registryUpdated) {
                    Write-ToLog -Message "Migration revert completed with registry update error. $revertedCount of $totalFiles registry files reverted but ProfileImagePath update failed." -Level Warning -Step "Revert-Migration"
                } else {
                    Write-ToLog -Message "Migration revert completed with errors. $revertedCount of $totalFiles registry files reverted. Registry updated: $registryUpdated" -Level Warning -Step "Revert-Migration"
                }
            } else {
                Write-ToLog -Message "DryRun mode completed. No actual changes were made." -Level Info -Step "Revert-Migration"
                $revertResult.Success = $true
            }
            #endregion Final Validation

        } catch {
            $errorMsg = "Migration revert failed: $($_.Exception.Message)"
            Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
            $revertResult.Errors += $errorMsg
            Write-ToProgress -ProgressBar $ProgressBar -Status $errorMsg -form $form -logLevel "Error"
        }
    }

    End {
        $revertResult.EndTime = Get-Date
        $duration = $revertResult.EndTime - $revertResult.StartTime

        Write-ToLog -Message "ADMU migration revert process completed in $($duration.TotalSeconds) seconds" -Level Info -Step "Revert-Migration"

        if ($revertResult.Success) {
            Write-ToLog -Message "Migration Revert End" -MigrationStep -Level Info
            Write-ToLog -message "Reverted UserSID: $UserSID" -Level Info -Step "Revert-Migration"
        } else {
            Write-ToLog -Message "Migration revert failed for SID: $UserSID. Errors: $($revertResult.Errors -join '; ')" -Level Error -Step "Revert-Migration"
        }

        return $revertResult
    }
}

