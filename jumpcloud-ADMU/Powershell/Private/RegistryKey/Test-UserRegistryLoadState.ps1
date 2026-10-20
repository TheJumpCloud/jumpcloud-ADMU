Function Test-UserRegistryLoadState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # User Security Identifier
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]$UserSid,
        [Parameter(Mandatory = $false)]
        [bool]$ValidateDirectory
    )
    begin {
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded, attempting to unload" -Level Verbose -Step "Test-UserRegistryLoadState"
            try {
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
            } catch {
                Write-AdmuErrorMessage -Error:("load_unload_error")
                Throw "Could Not Unload User Registry During Test-UserRegistryLoadState Unload Process"
            }
        }
    }
    process {
        # end{} does not run when process{} throws, so a failure here must unload the hives itself
        $validationsPassed = $false
        try {
            try {
                Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
                Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
            } catch {
                Write-AdmuErrorMessage -Error:("load_unload_error")
                Throw "Could Not Load User Registry During Test-UserRegistryLoadState Load Process"
            }
            # Validations during the load process
            if ($ValidateDirectory) {
                # return boolean for redirected user directories
                $isFolderRedirect = Test-UserFolderRedirect -UserSid $UserSid
            } else {
                Write-ToLog "Skipping User Shell Folder Validation..." -Level Verbose -Step "Test-UserRegistryLoadState"
            }

            # Check for previousSid from \Software\JCADMU
            if (Test-PreviousSID -UserSid $UserSid) {
                Write-AdmuErrorMessage -Error:("user_profile_previous_sid_error")
                Throw "User $($UserSid) has already been migrated. Exiting..."
            }
            # Validate the wallpaper policy
            Set-WallpaperPolicy -UserSid $UserSid
            ##### End of Validations #####
            $validationsPassed = $true
        } finally {
            if (-not $validationsPassed) {
                # Best effort. Errors are logged and not thrown so the original failure reaches the caller.
                try {
                    $loadedHives = REG QUERY HKU *>&1
                    $hivesToUnload = @(
                        @{ Name = "$($UserSid)_admu"; Hive = "root" },
                        @{ Name = "$($UserSid)_Classes_admu"; Hive = "classes" }
                    )
                    foreach ($hiveToUnload in $hivesToUnload) {
                        if ($loadedHives -match "\\$([regex]::Escape($hiveToUnload.Name))\s*$") {
                            Write-ToLog "Validation did not pass, unloading HKU\$($hiveToUnload.Name)" -Level Verbose -Step "Test-UserRegistryLoadState"
                            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive $hiveToUnload.Hive
                        }
                    }
                } catch {
                    Write-ToLog "Could not unload HKU\$($UserSid) hives after a failed validation: $($_.Exception.Message)" -Level Warning -Step "Test-UserRegistryLoadState"
                }
            }
        }
        try {
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
            Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
        } catch {
            Write-AdmuErrorMessage -Error:("load_unload_error")

            Throw "Could Not Unload User Registry During Test-UserRegistryLoadState Unload Process"
        }
    }
    end {
        $results = REG QUERY HKU *>&1
        # Tests to check that the reg items are not loaded
        If ($results -match $UserSid) {
            Write-ToLog "REG Keys are loaded, attempting to unload" -Level Verbose -Step "Test-UserRegistryLoadState"
            try {
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
            } catch {
                Write-AdmuErrorMessage -Error:("load_unload_error")
                throw "Registry Keys are still loaded after Test-UserRegistryLoadState Testing Exiting..."
            }
        }
        # If isFolderRedirect is false throw error
        if ($isFolderRedirect -and $ValidateDirectory) {
            Write-AdmuErrorMessage -Error:("user_folder_redirection_error")
            throw "Default user directories are redirected, and the ValidateUserShellFolder parameter is set to true. The migration can not continue if the user directories are redirected. Exiting..."
        } elseif ($ValidateDirectory -eq $false) {
            Write-ToLog "Skipping User Shell Folder Validation..." -Level Verbose -Step "Test-UserRegistryLoadState"
        } else {
            Write-ToLog "Default user directories are not redirected for Usersid: $($UserSid), continuing..." -Level Verbose -Step "Test-UserRegistryLoadState"
        }
    }
}
