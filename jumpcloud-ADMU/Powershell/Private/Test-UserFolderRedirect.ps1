# Function to validate that the user main folders are default and not redirected
function Test-UserFolderRedirect {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserSid
    )
    begin {
        if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
            Write-ToLog "Mounting HKEY_USERS"
            New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
        }
        $UserFolders = @( "Desktop", "Documents", "Downloads", "Favorites", "Music", "Pictures", "Videos" )
        # Support doc for personal folders: https://support.microsoft.com/en-us/topic/operation-to-change-a-personal-folder-location-fails-in-windows-ffb95139-6dbb-821d-27ec-62c9aaccd720
        $regFoldersPath = "HKEY_USERS:\$($UserSid)_admu\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        Write-ToLog -Message:("Checking User Shell Folders for USERSID: $($UserSid)")
    }
    process {

        if (Test-Path -Path $regFoldersPath) {
            $redirectedDirectory = $false
            # Save all the boolean to a hash table
            foreach ($userFolder in $UserFolders) {
                switch ($userFolder) {
                    "Desktop" {
                        $folderRegKey = "Desktop"
                    }
                    "Documents" {
                        $folderRegKey = "Personal"
                    }
                    "Downloads" {
                        $folderRegKey = "{374DE290-123F-4565-9164-39C4925E467B}"
                    }
                    "Favorites" {
                        $folderRegKey = "Favorites"
                    }
                    "Music" {
                        $folderRegKey = "My Music"
                    }
                    "Pictures" {
                        $folderRegKey = "My Pictures"
                    }
                    "Videos" {
                        $folderRegKey = "My Video"
                    }
                }
                # Get the registry value for the user folder
                $folderRegKeyValue = (Get-Item -path $regFoldersPath ).GetValue($folderRegKey , '', 'DoNotExpandEnvironmentNames')
                $defaultRegFolder = "%USERPROFILE%\$userFolder"
                # If the registry value does not match the default path, set redirectedDirectory to true and log the error
                if ($folderRegKeyValue -ne $defaultRegFolder) {
                    Write-ToLog -Message:("$($userFolder) path value: $($folderRegKeyValue) does not match default path  - $($defaultRegFolder)") -Level Error
                    $redirectedDirectory = $true
                } else {
                    Write-ToLog -Message:("User Shell Folder: $($userFolder) is default")
                }
            }
        } else {
            # If the registry path does not exist, set redirectedDirectory to true and log the error
            Write-ToLog -Message:("User Shell registry folders not found in registry") -Level Error
            $redirectedDirectory = $true
        }
    }
    end {
        return $redirectedDirectory
    }
}