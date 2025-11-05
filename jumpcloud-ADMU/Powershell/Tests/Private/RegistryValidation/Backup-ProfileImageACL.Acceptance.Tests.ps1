Describe "Backup-ProfileImageACL Acceptance Tests" -Tag "Acceptance" {
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

    Context 'Validate Backup-ProfileImageACL Function' {
        It 'Validate that Backup-ProfileImageACL creates a backup file' {
            # Call the function with valid parameters
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $profileImagePath = "C:\Users\TestUser" # Test User profile path since the runner denies access to some APPData folders

            Backup-ProfileImageACL -ProfileImagePath $profileImagePath -sourceSID $currentUserSID

            # Get the list of files in the backup directory
            $backupFile = Get-ChildItem -Path "$profileImagePath\AppData\Local\JumpCloudADMU" -Force
            $expectedPattern = "$currentUserSID`_permission_backup_*"
            $backupFile = $backupFile | Where-Object { $_.Name -like $expectedPattern }
            Write-Host "Backup files found: $($backupFile.Count)"
            # Assert that at least one file matches the expected pattern
            $backupFile.Count | Should -Be 1

            # Clean up created backup files after test
            foreach ($file in $backupFile) {
                Remove-Item -Path $file.FullName -Force
            }
        }

        It 'Validates for Invalid ProfileImagePath' {
            $invalidProfileImagePath = "Z:\Windows" # Path
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $mockErrorMessage = "Access is denied"

            Mock -CommandName 'Write-ToLog' -Verifiable

            Mock -CommandName 'New-Item' -MockWith {
                throw $mockErrorMessage
            }

            # # Should not throw since we do not throw, only Warn
            { Backup-ProfileImageACL -ProfileImagePath $invalidProfileImagePath -sourceSID $currentUserSID } | Should -Not -Throw

            # Verify that Write-ToLog was called by the catch block with the expected error message.
            $expectedLogPattern = "Error occurred while backing up permissions: $mockErrorMessage"

            Assert-MockCalled -CommandName 'Write-ToLog' -Scope It -Times 1 -ParameterFilter {
                $Message -like $expectedLogPattern -and $Level -eq 'Warning'
            }
        }

        It 'Handles terminating errors from icacls' {
            # Use valid inputs so the function proceeds to the icacls call
            $profileImagePath = "C:\Users\TestUser"
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $mockErrorMessage = "Simulated icacls failure: Access is denied."

            # Mock Write-ToLog to verify the catch block is hit
            Mock -CommandName 'Write-ToLog' -Verifiable

            # Mock the 'icacls' external command to throw a terminating error
            Mock -CommandName 'icacls' -MockWith {
                throw $mockErrorMessage
            }

            # Should not throw since we do not throw, only Warn
            { Backup-ProfileImageACL -ProfileImagePath $profileImagePath -sourceSID $currentUserSID } | Should -Not -Throw

            # Verify that Write-ToLog was called by the catch block with the expected error message
            $expectedLogPattern = "Error occurred while backing up permissions: $mockErrorMessage"

            Assert-MockCalled -CommandName 'Write-ToLog' -Scope It -Times 1 -ParameterFilter {
                $Message -like $expectedLogPattern -and $Level -eq 'Warning'
            }
        }

    }
}

