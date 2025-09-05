# Function to validate that the user main folders are default and not redirected
function Test-UserFolderRedirect {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $UserSid,
        [Parameter(HelpMessage = 'Use the _admu path (true) or the regular path (false). Defaults to true.')]
        [System.Boolean]
        $UseAdmuPath = $true

    )
    begin {
        # TODO: replace with Set-HKEYUsersMount
        # TODO: CUT-4890 Replace PSDrive with private function
        if ("HKEY_USERS" -notin (Get-PSDrive | select-object name).Name) {
            Write-ToLog "Mounting HKEY_USERS"
            New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
        }
        $UserFolders = @( "Desktop", "Documents", "Downloads", "Favorites", "Music", "Pictures", "Videos" )
        # Support doc for personal folders: https://support.microsoft.com/en-us/topic/operation-to-change-a-personal-folder-location-fails-in-windows-ffb95139-6dbb-821d-27ec-62c9aaccd720
        $basePath = "HKEY_USERS:\$($UserSid)"
        $pathSuffix = "\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        if ($UseAdmuPath) {
            $fullPath = "$($basePath)_admu$($pathSuffix)"
        } else {
            $fullPath = "$($basePath)$($pathSuffix)"
        }
        Write-ToLog -Message:("Checking User Shell Folders for USERSID: $($UserSid)")
    }
    process {

        if (Test-Path -Path $fullPath) {
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
                $folderRegKeyValue = (Get-Item -path $fullPath ).GetValue($folderRegKey , '', 'DoNotExpandEnvironmentNames')
                #$defaultRegFolder = "%USERPROFILE%\$userFolder"
                # If the registry value does not match the default path, set redirectedDirectory to true and log the error
                $regex = '^\\\\[a-zA-Z0-9.-]+\\[a-zA-Z0-9._-]+(\\[a-zA-Z0-9._-]+)*$' # regex for network paths ie \\server\share\folder, \\server.example.com\share\folder
                if ($folderRegKeyValue -match $regex) {
                    Write-ToLog -Message:("$($userFolder) path value: $($folderRegKeyValue) is a network path (IP or Domain). Migration NOT allowed.") -Level warn
                    $redirectedDirectory = $true
                } else {
                    Write-ToLog -Message:("$($userFolder) path value: $($folderRegKeyValue). Migration allowed.")
                }
            }
        } else {
            # If the registry path does not exist, set redirectedDirectory to true and log the error
            Write-ToLog -Message:("User Shell registry folders not found in registry") -Level warn
            $redirectedDirectory = $true
        }
    }
    end {
        return $redirectedDirectory
    }
}