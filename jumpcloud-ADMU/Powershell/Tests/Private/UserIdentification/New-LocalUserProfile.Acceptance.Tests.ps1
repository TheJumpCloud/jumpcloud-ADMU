Describe "New-LocalUserProfile Acceptance Tests" {
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
    }
    It "Should create a new profile and create the profile image path in registry" {
        # create a new local user
        $tempPassword = "Temp123!Temp123!"
        $tempUsername = "Temp1234"
        $tempPass = ConvertTo-SecureString -String $tempPassword -AsPlainText -Force

        # create the new user:
        New-localUser -Name $tempUsername -password $tempPass -Description "Created By JumpCloud ADMU"
        # init the user
        $NewUserSID = New-LocalUserProfile -username:($tempUsername)
        # the new user sid should return the username:
        $username = Convert-SecurityIdentifier -sid $NewUserSID
        $username | should -Be "$env:ComputerName\$tempUsername"
        # the user should have a valid profileImagePath
        $profileImagePath = Get-ProfileImagePath -UserSid $NewUserSID
        $profileImagePath | Should -Exist
        # remove the user to clean up the test
        Remove-LocalUserProfile -username $tempUsername
    }
}
