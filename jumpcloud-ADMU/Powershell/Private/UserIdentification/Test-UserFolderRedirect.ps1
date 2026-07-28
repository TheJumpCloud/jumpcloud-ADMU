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
        $UserFolders = @( "Desktop", "Documents", "Downloads", "Favorites", "Music", "Pictures", "Videos" )
        # Support doc for personal folders: https://support.microsoft.com/en-us/topic/operation-to-change-a-personal-folder-location-fails-in-windows-ffb95139-6dbb-821d-27ec-62c9aaccd720
        $hiveRoot = if ($UseAdmuPath) {
            "$($UserSid)_admu"
        } else {
            $UserSid
        }
        $shellFoldersPath = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        Write-ToLog -Message:("Checking User Shell Folders for USERSID: $($UserSid)") -Level Verbose -Step "Test-UserFolderRedirect"
    }
    process {
        $shellFoldersKey = $null
        try {
            $shellFoldersKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($shellFoldersPath)
            if ($null -eq $shellFoldersKey) {
                Write-ToLog -Message:("User Shell registry folders not found in registry") -Level Warning -Step "Test-UserFolderRedirect"
                $redirectedDirectory = $true
            } else {
                $redirectedDirectory = $false
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
                    # DoNotExpandEnvironmentNames equivalent: GetValue(name, default, RegistryValueOptions.DoNotExpandEnvironmentNames)
                    $folderRegKeyValue = $shellFoldersKey.GetValue(
                        $folderRegKey,
                        '',
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                    )
                    $regex = '^\\\\[a-zA-Z0-9.-]+\\[a-zA-Z0-9._-]+(\\[a-zA-Z0-9._-]+)*$' # regex for network paths ie \\server\share\folder, \\server.example.com\share\folder
                    if ($folderRegKeyValue -match $regex) {
                        Write-ToLog -Message:("$($userFolder) path value: $($folderRegKeyValue) is a network path (IP or Domain). Users can be migrated in this state but be aware that they might not be able to access their files if the location is unavailable post-migration. If you encounter this issue and would like to migrate this user anyways, please use the ValidateUserShellFolder parameter and set the value to false") -Level Warning -Step "Test-UserFolderRedirect"
                        $redirectedDirectory = $true
                    }
                }
            }
        } finally {
            if ($null -ne $shellFoldersKey) {
                $shellFoldersKey.Close()
                $shellFoldersKey.Dispose()
            }
        }
    }
    end {
        return $redirectedDirectory
    }
}
