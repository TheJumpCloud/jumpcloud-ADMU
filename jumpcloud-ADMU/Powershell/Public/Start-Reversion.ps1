function Start-Reversion {
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
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "The Windows Security Identifier (SID) of the user account to revert. Can be either the SID or the SID with .bak suffix. Example: S-1-5-21-123456789-1234567890-123456789-1001 or S-1-5-21-123456789-1234567890-123456789-1001.bak")]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+(?:\.bak)?$")]
        [string]$UserSID,

        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "The actual profile path to revert. If not specified, will use the path from the registry. This path will be validated to ensure it exists and is associated with the UserSID.")]
        [ValidateScript({
                if (Test-Path $_ -PathType Container) { $true }
                else { throw "Target profile path does not exist: $_" }
            })]
        [string]$TargetProfileImagePath,
        [Parameter(Mandatory = $false, HelpMessage = "The form parameter specifies whether to launch the reversion process in a graphical user interface (GUI) form. For CLI usage, this parameter should be set to false.")]
        [bool]$form = $false,
        [Parameter(Mandatory = $false, HelpMessage = "Shows what actions would be performed without actually executing them.")]
        [switch]$DryRun,
        [Parameter(Mandatory = $false, HelpMessage = "Bypasses confirmation prompts and forces the revert operation.")]
        [switch]$Force
    )

    begin {
        Write-ToLog -Message "Begin Revert Migration" -MigrationStep -Level Info

        # Normalize UserSID by removing .bak suffix if present
        $UserSID = $UserSID -replace '\.bak$', ''

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

        # Regex pattern to identify .ADMU profile paths
        $admuPathPattern = '\.ADMU$'

        # Status message map for reversion steps
        $revertMessageMap = [Ordered]@{
            revertInit                  = @{
                step = "Initializing"
                desc = "Initializing the profile reversion process."
            }
            revertValidateProfilePath   = @{
                step = "Validating Profile Registry Path"
                desc = "Validating the profile path exists in the registry."
            }
            revertValidateRegistryFiles = @{
                step = "Validating Registry Files"
                desc = "Validating the integrity of the registry files to be reverted."
            }
            revertRegistryFiles         = @{
                step = "Restoring Registry Files"
                desc = "Restoring the original registry files."
            }
            revertProfileImagePath      = @{
                step = "Restoring ProfileImagePath"
                desc = "Restoring the ProfileImagePath value in the registry."
            }
            revertProfileACLs           = @{
                step = "Restoring Profile Permissions"
                desc = "Restoring the profile owner and Access Control List (ACL) permissions via Set-RegPermission."
            }
            revertRemoveJCUserArtifacts = @{
                step = "Removing JumpCloud Artifacts"
                desc = "Removing JumpCloud user artifacts created during the initial process."
            }
            revertComplete              = @{
                step = "Reversion Complete"
                desc = "Profile Reversion completed successfully."
            }
        }

        # Profile size is calculated in process after the profile path is resolved from the registry.
        $profileSize = $null
        # Prefer the progress form created in Form.ps1 so updates apply to the first window the user sees
        if ((-not $script:ProgressBar) -and ($form)) {
            $script:ProgressBar = New-ProgressForm
        }

        $ProgressBar = $script:ProgressBar
    }

    process {
        try {
            $account = New-Object System.Security.Principal.SecurityIdentifier($UserSID)
            try {
                $domainUser = ($account.Translate([System.Security.Principal.NTAccount])).Value
            } catch {
                Write-ToLog -Message "Warning: Could not translate UserSID $UserSID to NTAccount. Using SID string instead." -Level Verbose -Step "Revert-Migration"
                $domainUser = $UserSID
            }

            Write-ToLog -Message "Validating user SID: $UserSID" -Level Verbose -Step "Revert-Migration"

            # VALIDATION: Check if user profile is currently loaded
            if (Test-UserProfileLoaded -UserSID $UserSID) {
                $errorMessage = "Cannot revert user profile for SID: $UserSID. The user's profile is currently loaded in memory. Please ensure the user is logged out before attempting reversion."
                Write-ToLog -Message $errorMessage -Level Error
                throw $errorMessage
            }

            #region Validate Registry and Determine Profile Path
            Write-ToLog -Message "Looking up profile information for SID: $UserSID" -Level Info -Step "Revert-Migration"

            $profileRegistryBasePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID"
            $profileRegistryBakPath = "$profileRegistryBasePath.bak"
            $profileRegistryOldPath = "$profileRegistryBasePath.old"
            $switchedToBak = $false

            # Check for the rare instance where both base and .bak SID keys exist
            if ((Test-Path -LiteralPath $profileRegistryBasePath) -and (Test-Path -LiteralPath $profileRegistryBakPath)) {
                Write-ToLog -Message "Detected both base and .bak registry keys for SID: $UserSID" -Level Info -Step "Revert-Migration"
                try {
                    $bakProfileImagePath = (Get-ItemProperty -Path $profileRegistryBakPath -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath

                    # Validate if .bak matches the target path with .ADMU suffix or just has the .ADMU suffix
                    $isMatch = $false
                    if ($TargetProfileImagePath -and ($bakProfileImagePath -eq "$TargetProfileImagePath.ADMU")) {
                        $isMatch = $true
                    } elseif ($bakProfileImagePath -match $admuPathPattern) {
                        $isMatch = $true
                    }

                    if ($isMatch) {
                        Write-ToLog -Message ".bak registry key verified as the .ADMU profile: $bakProfileImagePath" -Level Info -Step "Revert-Migration"

                        if (-not $DryRun) {
                            # Clean up an existing .old key if it's lingering around
                            if (Test-Path -LiteralPath $profileRegistryOldPath) {
                                Remove-Item -Path $profileRegistryOldPath -Recurse -Force -ErrorAction SilentlyContinue
                            }
                            Write-ToLog -Message "Appending .old to the base registry key to clear the path for the correct profile." -Level Info -Step "Revert-Migration"
                            Rename-Item -LiteralPath $profileRegistryBasePath -NewName "$UserSID.old" -Force -ErrorAction Stop
                        } else {
                            Write-ToLog -Message "WHAT IF: Would append .old to base registry key $profileRegistryBasePath." -Level Verbose -Step "Revert-Migration"
                        }

                        # Switch variables to use the .bak path
                        $profileRegistryPath = $profileRegistryBakPath
                        $registryProfileImagePath = $bakProfileImagePath
                        $switchedToBak = $true
                    } else {
                        Write-ToLog -Message ".bak key exists but does not match expected .ADMU pattern. Checking base key." -Level Warning -Step "Revert-Migration"
                    }
                } catch {
                    Write-ToLog -Message "Could not read .bak registry key: $($_.Exception.Message)" -Level Warning -Step "Revert-Migration"
                }
            }

            # If the dual-SID logic didn't trigger, resolve via standard method
            if (-not $switchedToBak) {
                $profileRegistryPath = (Get-ProfileRegistryPath -UserSID $UserSID).ResolvedPath
                $registryProfileImagePath = (Get-ItemProperty -Path $profileRegistryPath -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath
            }

            $revertResult.RegistryProfilePath = $registryProfileImagePath
            $originalRegistryProfileImagePath = $registryProfileImagePath

            Write-ToLog -Message "Found registry profile path: $registryProfileImagePath" -Level Info -Step "Revert-Migration"

            # Validate this is an ADMU migrated profile by checking registry path
            if ($registryProfileImagePath -notmatch $admuPathPattern) {
                throw "Registry profile path does not contain .ADMU suffix. This does not appear to be a migrated profile: $registryProfileImagePath"
            } else {
                Write-ToLog -Message "Confirmed .ADMU migration profile detected in registry" -Level Verbose -Step "Revert-Migration"
            }

            # Determine which profile path to use
            if ($TargetProfileImagePath) {
                Write-ToLog -Message "Using provided target profile path: $TargetProfileImagePath" -Level Info -Step "Revert-Migration"
                $profileImagePath = $TargetProfileImagePath

                # Validate target profile path is associated with the UserSID
                $skipValidation = $false
                if ($switchedToBak -and (($bakProfileImagePath -replace $admuPathPattern, '') -eq $TargetProfileImagePath)) {
                    Write-ToLog -Message "Target profile path strictly matches validated .bak registry entry. Skipping secondary validation." -Level Verbose -Step "Revert-Migration"
                    $skipValidation = $true
                }

                if (-not $skipValidation) {
                    $sidValidation = Confirm-ProfileSidAssociation -ProfilePath $TargetProfileImagePath -UserSID $UserSID
                    if (-not $sidValidation.IsValid) {
                        throw "Target profile path validation failed: $($sidValidation.Reason)"
                    } else {
                        Write-ToLog -Message "Target profile path validated for UserSID: $UserSID" -Level Verbose -Step "Revert-Migration"
                    }
                }
            } else {
                # Use registry path, remove .ADMU suffix
                $profileImagePath = $registryProfileImagePath -replace $admuPathPattern, ''

                if (-not $switchedToBak) {
                    $sidValidation = Confirm-ProfileSidAssociation -ProfilePath $profileImagePath -UserSID $UserSID
                    if (-not $sidValidation.IsValid) {
                        throw "Registry profile path validation failed: $($sidValidation.Reason)"
                    }
                } else {
                    Write-ToLog -Message "Skipping profile path validation since successfully switched to .bak registry key" -Level Verbose -Step "Revert-Migration"
                }
                Write-ToLog -Message "Using registry profile path (without .ADMU): $profileImagePath" -Level Info -Step "Revert-Migration"
            }

            $revertResult.ActualProfilePath = $profileImagePath

            if ($form -and -not [string]::IsNullOrWhiteSpace($profileImagePath)) {
                try {
                    $profileSize = Get-ProfileSize -profilePath $profileImagePath
                } catch {
                    Write-ToLog -Message "Could not calculate profile size: $($_.Exception.Message)" -Level Verbose -Step "Revert-Migration"
                    $profileSize = 'Unknown'
                }
            } else {
                $profileSize = 'N/A'
            }

            Write-ToProgress -form $form -Status "revertInit" -ProgressBar $ProgressBar -ProfileSize $profileSize -LocalPath $profileImagePath -StatusMap $revertMessageMap
            Write-ToProgress -form $form -Status "revertValidateProfilePath" -ProgressBar $ProgressBar -ProfileSize $profileSize -LocalPath $profileImagePath -StatusMap $revertMessageMap
            #endregion Validate Registry and Determine Profile Path

            #region Validate Profile Directory
            if (-not (Test-Path $profileImagePath -PathType Container)) {
                throw "Profile directory does not exist: $profileImagePath"
            }

            Write-ToLog -Message "Profile directory exists and is accessible" -Level Verbose -Step "Revert-Migration"
            Write-ToLog -Message "Profile path: $profileImagePath" -Level Verbose -Step "Revert-Migration"
            #endregion Validate Profile Directory

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
                throw "No NTUser.DAT backup files found in directory: $profileImagePath for SID: $UserSID. Cannot proceed with revert."
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
                throw "No UsrClass.dat backup files found in directory: $profileImagePath for SID: $UserSID. Cannot proceed with revert."
            }
            #endregion Identify Registry Files to Revert

            #region Validate Files Before Revert
            Write-ToProgress -form $form -Status "revertValidateRegistryFiles" -ProgressBar $ProgressBar -StatusMap $revertMessageMap
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
            Write-ToProgress -form $form -Status "revertRegistryFiles" -ProgressBar $ProgressBar -StatusMap $revertMessageMap
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
            Write-ToProgress -form $form -Status "revertProfileImagePath" -ProgressBar $ProgressBar -StatusMap $revertMessageMap
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

            #region Set Profile Permissions and Ownership
            if (-not $DryRun) {
                Write-ToProgress -form $form -Status "revertProfileACLs" -ProgressBar $ProgressBar -StatusMap $revertMessageMap
                Write-ToLog -Message "Setting profile ownership and permissions via Set-RegPermission for: $profileImagePath" -Level Info -Step "Revert-Migration"
                try {
                    Set-RegPermission -SourceSID $UserSID -TargetSID $UserSID -FilePath $profileImagePath -Recursive
                    Write-ToLog -Message "Successfully set profile ownership and permissions for: $profileImagePath" -Level Info -Step "Revert-Migration"
                } catch {
                    $errorMsg = "Failed to set profile permissions: $($_.Exception.Message)"
                    Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
                    $revertResult.Errors += $errorMsg
                }
            } else {
                Write-ToLog -Message "WHAT IF: Would set profile ownership and permissions on: $profileImagePath (Target SID: $UserSID)" -Level Verbose -Step "Revert-Migration"
            }
            #endregion Set Profile Permissions and Ownership

            #region Remove JumpCloud ADMU Created User
            $jcUsers = Get-LocalUser | Where-Object { $_.Description -eq 'Created by JumpCloud ADMU' }
            if (-not $DryRun) {
                # Check if the user has the $profileImagePath as profile path
                foreach ($jcUser in $jcUsers) {
                    #Get the profile path of the user
                    $jcUserProfilePath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($jcUser.SID.Value)" -Name "ProfileImagePath" -ErrorAction Stop).ProfileImagePath
                    # Compare the profile path with the $profileImagePath
                    if ($jcUserProfilePath -eq $profileImagePath) {
                        Write-ToLog -message "Removing JumpCloud created user: $($jcUser.Name)" -Level Info -Step "Revert-Migration"
                        Write-ToProgress -form $form -Status "revertRemoveJCUserArtifacts" -ProgressBar $ProgressBar -StatusMap $revertMessageMap
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

            #region Remove ProfileList SID.bak Entry
            if ($profileRegistryBakPath) {
                if ($DryRun) {
                    if (Test-Path -LiteralPath $profileRegistryBakPath) {
                        if ($profileRegistryPath -eq $profileRegistryBakPath) {
                            Write-ToLog -Message "WHAT IF: Would rename registry entry $profileRegistryBakPath to $profileRegistryBasePath" -Level Verbose -Step "Revert-Migration"
                        } else {
                            Write-ToLog -Message "WHAT IF: Would remove registry entry $profileRegistryBakPath" -Level Verbose -Step "Revert-Migration"
                        }
                    } else {
                        Write-ToLog -Message "WHAT IF: No SID.bak registry entry found for SID: $UserSID" -Level Verbose -Step "Revert-Migration"
                    }
                } elseif (Test-Path -LiteralPath $profileRegistryBakPath) {
                    try {
                        # Check if the resolved profile registry path is the .bak path
                        if ($profileRegistryPath -eq $profileRegistryBakPath) {
                            # If we updated the .bak key, rename it to the base name instead of deleting it
                            if ($revertResult.RegistryUpdated) {
                                $basePath = $profileRegistryBasePath
                                Write-ToLog -Message "Renaming registry entry from $profileRegistryBakPath to $basePath" -Level Info -Step "Revert-Migration"
                                Rename-Item -LiteralPath $profileRegistryBakPath -NewName (Split-Path -Leaf $basePath) -Force -ErrorAction Stop
                                Write-ToLog -Message "Successfully renamed registry entry to $basePath" -Level Info -Step "Revert-Migration"
                            } else {
                                Write-ToLog -Message "Preserving registry entry $profileRegistryBakPath as recovery reference since ProfileImagePath update failed" -Level Warning -Step "Revert-Migration"
                            }
                        } else {
                            # Safe to remove the .bak entry if it's separate from the active profile path and registry update succeeded
                            if ($revertResult.RegistryUpdated) {
                                Write-ToLog -Message "Removing registry entry $profileRegistryBakPath" -Level Info -Step "Revert-Migration"
                                Remove-Item -LiteralPath $profileRegistryBakPath -Recurse -Force -ErrorAction Stop
                                Write-ToLog -Message "Successfully removed registry entry $profileRegistryBakPath" -Level Info -Step "Revert-Migration"
                            } else {
                                Write-ToLog -Message "Preserving registry entry $profileRegistryBakPath as recovery reference since ProfileImagePath update failed" -Level Warning -Step "Revert-Migration"
                            }
                        }
                    } catch {
                        $errorMsg = "Failed to process registry entry $profileRegistryBakPath : $($_.Exception.Message)"
                        Write-ToLog -Message $errorMsg -Level Error -Step "Revert-Migration"
                        $revertResult.Errors += $errorMsg
                    }
                } else {
                    Write-ToLog -Message "No SID.bak registry entry found for SID: $UserSID" -Level Verbose -Step "Revert-Migration"
                }
            }
            #endregion Remove ProfileList SID.bak Entry

            #region Final Validation
            if (-not $DryRun) {
                Write-ToLog -Message "Performing post-revert validation" -Level Info -Step "Revert-Migration"

                $revertedCount = $revertResult.FilesReverted.Count
                $totalFiles = $registryFiles.Count
                $registryUpdated = $revertResult.RegistryUpdated

                if ($revertedCount -eq $totalFiles -and $registryUpdated) {
                    $revertResult.Success = $true
                    Write-ToLog -Message "Migration revert completed successfully. $revertedCount of $totalFiles registry files reverted and registry ProfileImagePath updated." -Level Info -Step "Revert-Migration"
                    Write-ToProgress -form $form -Status "revertComplete" -ProgressBar $ProgressBar -StatusMap $revertMessageMap
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

    end {
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