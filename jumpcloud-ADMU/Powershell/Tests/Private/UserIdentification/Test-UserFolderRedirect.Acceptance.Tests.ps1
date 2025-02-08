Describe "Test-UserFolderRedirect Acceptance Tests" {
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
        }
        # Test for Test-UserFolderRedirect should be default values
        It 'Test-UserFolderRedirect - Default values' {
            $folderRedirect = Test-UserFolderRedirect -UserSid $userSid
            $folderRedirect | Should -Be $false
        }
        # Test for Test-UserFolderRedirect with one of the folder redirect values changed
        It 'Test-UserFolderRedirect - One value changed' {
            # Change the value of the folder Desktop to a different value
            $folderPath = "HKEY_USERS:\$($userSid)_admu\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            Set-ItemProperty -Path $folderpath -Name Desktop -Value "\\server\share\desktop"
            Test-UserFolderRedirect -UserSid $userSid | Should -Be $true
            # Change the value of the folder Desktop back to the default value
            Set-ItemProperty -Path $folderpath -Name Desktop -Value "%USERPROFILE%\Desktop"

        }
        # Test for Invalid SID or Invalid User Shell Folder
        It 'Test-UserFolderRedirect - Invalid SID or Invalid User Shell Folder' {
            Test-UserFolderRedirect -UserSid "Invalid-3361044348-30300820-1001" | Should -be $true
        }
    }
}
