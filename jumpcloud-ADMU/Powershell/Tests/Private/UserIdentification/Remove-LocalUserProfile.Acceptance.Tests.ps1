Describe "Remove-LocalUserProfile Acceptance Tests" -Tag "Acceptance" {
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
    It "Should not remove users created without the 'Created By JumpCloud ADMU' description" {
        # create a new local user
        $tempPassword = "Temp123!Temp123!"
        $tempUsername = "Temp1234"
        $tempPass = ConvertTo-SecureString -String $tempPassword -AsPlainText -Force

        # create the new user:
        New-localUser -Name $tempUsername -password $tempPass -Description "Not Created By JumpCloud ADMU"
        { Remove-LocalUserProfile -Username $tempUsername } | Should -Throw
        # remove the user to clean up after the test
        Remove-localUser -Name $tempUsername

    }
    It "Should remove users created without the 'Created By JumpCloud ADMU' description" {
        # create a new local user
        $tempPassword = "Temp123!Temp123!"
        $tempUsername = "Temp1234"
        $tempPass = ConvertTo-SecureString -String $tempPassword -AsPlainText -Force

        # create the new user:
        New-localUser -Name $tempUsername -password $tempPass -Description "Created By JumpCloud ADMU"
        # init the user
        $NewUserSID = New-LocalUserProfile -username:($tempUsername)
        $usersBefore = Get-LocalUser
        { Remove-LocalUserProfile -Username $tempUsername } | Should -Not -Throw
        # remove the user to clean up after the test
        $usersAfter = Get-LocalUser
        $tempUsername | Should -BeIn $usersBefore.Name
        $tempUsername | Should -Not -BeIn $usersAfter.Name
    }

    # Add more acceptance tests as needed
}
