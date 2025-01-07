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
            Write-ToLog "REG Keys are loaded, attempting to unload"
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
        try {
            Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid -hive root
            Set-UserRegistryLoadState -op "Load" -ProfilePath $ProfilePath -UserSid $UserSid -hive classes
            if ($ValidateDirectory) {
                # return boolean for redirected user directories
                $isFolderRedirect = Test-UserFolderRedirect -UserSid $UserSid
            } else {
                Write-ToLog "Skipping User Shell Folder Validation..."
            }
        } catch {
            Write-AdmuErrorMessage -Error:("load_unload_error")
            Throw "Could Not Load User Registry During Test-UserRegistryLoadState Load Process"
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
            Write-ToLog "REG Keys are loaded, attempting to unload"
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
            throw "Main user folders are redirected, exiting..."
        } elseif ($ValidateDirectory -eq $false) {
            Write-ToLog "Skipping User Shell Folder Validation..."
        } else {
            Write-ToLog "Main user folders are default for Usersid: $($UserSid), continuing..."
        }
    }
}
