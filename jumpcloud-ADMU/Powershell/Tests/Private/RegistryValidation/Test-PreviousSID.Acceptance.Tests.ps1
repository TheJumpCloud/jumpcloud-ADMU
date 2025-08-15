Describe "Test-PreviousSID Acceptance Tests" -Tag "Acceptance" {
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
    Context "Validate previousSid" {
        It 'Validates the function Test-PreviousSID returns $false if PreviousSID is not present' {
            if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS") {
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }
            #$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $newUser = "ADMU_User" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234adsasddasasd'
            Initialize-TestUser -UserName $newUser -Password $Password

            $userSid = Test-UsernameOrSID -usernameOrSid $newUser
            # Load the registry hive for the user and add _admu after the sid
            REG LOAD HKU\$($userSid)_admu "C:\Users\$newUser\NTUSER.DAT" *>&1
            # Run the test function
            # Should be empty
            Test-PreviousSID -UserSid $userSid | Should -Be $false
            # Clean up
        }

        It "Validates the function Test-PreviousSID returns $true if PreviousSID is present" {
            if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS") {
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }
            #$currentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $newUser = "ADMU_User" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234adsasddasasd'
            Initialize-TestUser -UserName $newUser -Password $Password

            $userSid = Test-UsernameOrSID -usernameOrSid $newUser
            # Load the registry hive for the user and add _admu after the sid
            REG LOAD HKU\$($userSid)_admu "C:\Users\$newUser\NTUSER.DAT" *>&1
            $folderPath = "HKEY_USERS:\$($userSid)_admu\Software\JCADMU"
            # Create the folder if it doesn't exist
            New-Item -Path $folderPath -Force | Out-Null
            Test-Path $folderPath | Should -Be $true
            # Set the PreviousSID value
            Set-ItemProperty -Path $folderPath -Name "previousSid" -Value "S-1-5-21-1234567890-1234567890-1234567890-1001" -Force

            # Run the test function
            Test-PreviousSID -UserSid $userSid | Should -Be $true
            # Clean up
            Remove-Item -Path $folderPath -Recurse -Force | Out-Null
        }

    }

}
