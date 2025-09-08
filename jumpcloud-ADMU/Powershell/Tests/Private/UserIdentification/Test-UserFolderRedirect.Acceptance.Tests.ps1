Describe "Test-UserFolderRedirect and Set-WallpaperPolicy Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"

        # import the helper functions:
        . "$helpFunctionDir\initialize-TestUser.ps1"
    }
    It "Should return a users redirection status, given a valid SID" {
        # Add acceptance test logic and assertions (against a real system)
        # get the current user SID
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        $sidResult = Test-UserFolderRedirect -userSid $currentUserSID -UseAdmuPath $false
        $sidResult | should -Be $false
    }

    Context 'Validates that the User shell folder for default values' {
        BeforeAll {
            # TODO: CUT-4890 Replace PSDrive with private function
            if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS") {
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }
            #$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $newUser = "ADMU_User" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $newUser -Password $Password

            $userSid = Test-UsernameOrSID -usernameOrSid $newUser
            # Load the registry hive for the user and add _admu after the sid
            REG LOAD HKU\$($userSid)_admu "C:\Users\$newUser\NTUSER.DAT" *>&1
            $folderPath = "HKEY_USERS:\$($userSid)_admu\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        }
        # Test for Test-UserFolderRedirect should be default values
        It 'Test-UserFolderRedirect - Default values' {
            $folderRedirect = Test-UserFolderRedirect -UserSid $userSid
            $folderRedirect | Should -Be $false
        }
        # Test for Test-UserFolderRedirect with one of the folder redirect values changed
        It 'Test-UserFolderRedirect - One value changed' {
            # Change the value of the folder Desktop to a different value
            Write-Output "Changing the value of the folder Desktop to a different value $($folderPath)"
            Set-ItemProperty -Path $folderpath -Name Desktop -Value "\\server\share\desktop"
            # Validate that the folder has changed
            (Get-ItemProperty -Path $folderpath).Desktop | Should -Be "\\server\share\desktop"
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $true
            # Change the value of the folder Desktop back to the default value
            Set-ItemProperty -Path $folderpath -Name Desktop -Value "%USERPROFILE%\Desktop"
        }
        # Test for Invalid SID or Invalid User Shell Folder
        It 'Test-UserFolderRedirect - Invalid SID or Invalid User Shell Folder' {
            Test-UserFolderRedirect -UserSid "Invalid-3361044348-30300820-1001" | Should -be $true
        }
        # Test for IP Path
        It 'Test-UserFolderRedirect - IP Path' {
            # Change the value of the folder Documents to an IP path
            Set-ItemProperty -Path $folderpath -Name "My Music" -Value "\\192.168.1.10\SharedFolder\Music"
            # Validate that the folder has changed
            (Get-ItemProperty -Path $folderpath)."My Music" | Should -Be "\\192.168.1.10\SharedFolder\Music"
            # Test path
            Write-Host $userSid
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $true
            # Change the value of the folder Documents back to the default value
            Set-ItemProperty -Path $folderpath -Name "My Music" -Value "%USERPROFILE%\Music"
        }
        # Test for Domain Path
        It 'Test-UserFolderRedirect - Domain Path' {
            # Change the value of the folder Documents to a domain path
            Set-ItemProperty -Path $folderpath -Name Desktop -Value "\\domain.local\SharedFolder\Desktop"
            # Validate that the folder has changed
            (Get-ItemProperty -Path $folderpath).Desktop | Should -Be "\\domain.local\SharedFolder\Desktop"
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $true
            # Change the value of the folder Desktop back to the default value
            Set-ItemProperty -Path $folderpath -Name Desktop -Value "%USERPROFILE%\Desktop"
        }
        It 'Test-UserFolderRedirect - My Drive (GDrive)' {
            # Change the value of the folder Documents to a Google Drive path/different drive letter
            # Note: This is a test for a Google Drive path, but it can be adapted for any other drive letter
            Set-ItemProperty -Path $folderpath -Name "{374DE290-123F-4565-9164-39C4925E467B}" -Value "G:\My Drive\Downloads" # Using the Downloads ID
            # Validate that the folder has changed
            (Get-ItemProperty -Path $folderpath)."{374DE290-123F-4565-9164-39C4925E467B}" | Should -Be "G:\My Drive\Downloads"
            # Test path
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $false

            Set-ItemProperty -Path $folderpath -Name "{374DE290-123F-4565-9164-39C4925E467B}" -Value "%USERPROFILE%\Downloads"
        }
        # Test for OneDrive in the path
        It 'Test-UserFolderRedirect - OneDrive' {
            # Change the value of the folder Documents to a OneDrive path
            Set-ItemProperty -Path $folderpath -Name Documents -Value "C:\Users\$newUser\OneDrive\Documents"
            # Validate that the folder has changed
            (Get-ItemProperty -Path $folderpath).Documents | Should -Be "C:\Users\$newUser\OneDrive\Documents"

            # Test path
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $false

            # Set the folder values back to default
            Set-ItemProperty -Path $folderpath -Name Documents -Value "%USERPROFILE%\Documents"
        }
        # Test for a default value for the folder path
        It 'Test-UserFolderRedirect - Default value for the folder path' {
            # Change the value of the folder Documents to a default value
            Set-ItemProperty -Path $folderpath -Name Documents -Value "%USERPROFILE%\Documents"
            # Validate that the folder has changed
            (Get-ItemProperty -Path $folderpath).Documents | Should -Be "%USERPROFILE%\Documents"
            # Test path
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $false
        }
    }

    Context 'Validates Wallpaper Policy Removal' {
        BeforeAll {
            # TODO: CUT-4890 Replace PSDrive with private function
            if ((Get-psdrive | Select-Object -ExpandProperty Name) -notmatch "HKEY_USERS") {
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }

            #$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $newUser = "ADMU_User" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $newUser -Password $Password

            $userSid = Test-UsernameOrSID -usernameOrSid $newUser
            # Load the registry hive for the user and add _admu after the sid
            REG LOAD HKU\$($userSid)_admu "C:\Users\$newUser\NTUSER.DAT" *>&1
            # This context reuses the $userSid and loaded hive from the previous context.
            $policyPath = "HKEY_USERS:\$($userSid)_admu\Software\Microsoft\Windows\CurrentVersion\Policies\System"
            # Ensure the parent key exists for testing.
            if (-not (Test-Path $policyPath)) {
                New-Item -Path $policyPath -Force | Out-Null
            }
        }

        It 'Should remove wallpaper policy' {
            # Set a network wallpaper policy
            Set-ItemProperty -Path $policyPath -Name "Wallpaper" -Value "\\Server\Share\wallpaper.jpg"
            Set-ItemProperty -Path $policyPath -Name "WallpaperStyle" -Value "2"

            # Run the function to test removal
            Set-WallpaperPolicy -UserSid $userSid

            # Verify the properties are removed
            $wallpaperProp = Get-ItemProperty -Path $policyPath -Name "Wallpaper" -ErrorAction SilentlyContinue
            $wallpaperStyleProp = Get-ItemProperty -Path $policyPath -Name "WallpaperStyle" -ErrorAction SilentlyContinue
            $wallpaperStyleProp | Should -BeNull
            $wallpaperProp | Should -BeNull
        }

        It 'Should run without error when no policy is set' {
            # Ensure no policies are set before the test
            Remove-ItemProperty -Path $policyPath -Name "Wallpaper", "WallpaperStyle" -ErrorAction SilentlyContinue

            # The function should execute without throwing an error
            { Set-WallpaperPolicy -UserSid $userSid } | Should -Not -Throw
        }
    }
}
