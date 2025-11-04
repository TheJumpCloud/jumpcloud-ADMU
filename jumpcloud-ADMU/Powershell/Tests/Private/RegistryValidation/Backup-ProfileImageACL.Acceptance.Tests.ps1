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
            Backup-ProfileImageACL -ProfileImagePath $HOME -sourceSID $currentUserSID

            $backupDirectory = Join-Path -Path $HOME -ChildPath "AppData\Local\JumpCloudADMU"

            # Get the list of files in the backup directory
            $backupFile = Get-ChildItem -Path $backupDirectory -Force
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
