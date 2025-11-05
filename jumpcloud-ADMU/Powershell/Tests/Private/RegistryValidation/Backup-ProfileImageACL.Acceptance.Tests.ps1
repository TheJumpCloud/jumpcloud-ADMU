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
        It 'Validate that Backup-ProfileImageACL creates a backup file with hidden attribute' {
            # Call the function with valid parameters
            $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
            $profileImagePath = "C:\Users\TestUser" # Test User profile path since the runner denies access to some APPData folders
            Backup-ProfileImageACL -ProfileImagePath $profileImagePath -sourceSID $currentUserSID

            $path = $profileImagePath + '\AppData\Local\JumpCloudADMU'
            If (!(test-path $path)) {
                New-Item -ItemType Directory -Force -Path $path | Out-Null
            }

            # Get the list of files in the backup directory
            $backupFile = Get-ChildItem -Path $path -Force
            $expectedPattern = "$currentUserSID`_permission_backup_*"
            $backupFile = $backupFile | Where-Object { $_.Name -like $expectedPattern }

            # Assert that at least one file matches the expected pattern
            $backupFile.Count | Should -Be 1

            # Clean up created backup files after test
            foreach ($file in $backupFile) {
                Remove-Item -Path $file.FullName -Force
            }
        }
    }
}
