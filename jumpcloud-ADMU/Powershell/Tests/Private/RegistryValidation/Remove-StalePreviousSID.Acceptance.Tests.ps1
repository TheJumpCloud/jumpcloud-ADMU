Describe "Remove-StalePreviousSID Acceptance Tests" -Tag "Acceptance" {
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
    BeforeEach {
        Set-HKEYUserMount
        $newUser = "ADMU_User" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $password = '$T#st1234adsasddasasd'
        Initialize-TestUser -UserName $newUser -Password $Password
        $userSid = Test-UsernameOrSID -usernameOrSid $newUser
        REG LOAD HKU\$($userSid)_admu "C:\Users\$newUser\NTUSER.DAT" *>&1
        $folderPath = "HKEY_USERS:\$($userSid)_admu\Software\JCADMU"
        New-Item -Path $folderPath -Force | Out-Null
        Set-ItemProperty -Path $folderPath -Name "previousSid" -Value $userSid -Force
        Set-ItemProperty -Path $folderPath -Name "previousProfilePath" -Value "C:\Users\$newUser" -Force
    }
    It "Removes the JCADMU key when only the marker values were in it" {
        Remove-StalePreviousSID -UserSid $userSid
        Test-Path $folderPath | Should -BeFalse
    }
    It "Keeps the JCADMU key and its other values when something else is stored in it" {
        Set-ItemProperty -Path $folderPath -Name "otherValue" -Value "keep" -Force

        Remove-StalePreviousSID -UserSid $userSid

        $remaining = Get-ItemProperty -Path $folderPath
        $remaining.otherValue | Should -Be "keep"
        $remaining.PSObject.Properties.Name | Should -Not -Contain "previousSid"
        $remaining.PSObject.Properties.Name | Should -Not -Contain "previousProfilePath"
    }
    It "Does nothing when the JCADMU key does not exist" {
        Remove-Item -Path $folderPath -Recurse -Force
        { Remove-StalePreviousSID -UserSid $userSid } | Should -Not -Throw
    }
}
