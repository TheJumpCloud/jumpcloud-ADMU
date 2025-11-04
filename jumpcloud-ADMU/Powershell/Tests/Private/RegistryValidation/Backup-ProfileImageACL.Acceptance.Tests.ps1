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
        $profileImagePath = $env:USERPROFILE
        $currentSid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value


    }

    Context 'Validate Backup-ProfileImageACL Function' {
        It 'Validate that Backup-ProfileImageACL creates a backup file with hidden attribute' {
            # Call the function with valid parameters
            $Output = Backup-ProfileImageACL -ProfileImagePath $profileImagePath -sourceSID $currentSid

            $backupDirectory = Join-Path -Path $profileImagePath -ChildPath "AppData\Local\JumpCloudADMU"

            # Get the list of files in the backup directory
            $backupFile = Get-ChildItem -Path $backupDirectory -Force

            # Assert that at least one file matches the expected pattern
            $backupFile.Count | Should -Be 1

            $backupFile.Attributes.ToString() | Should -Match "Hidden"

            # Clean up created backup files after test
            foreach ($file in $backupFile) {
                Remove-Item -Path $file.FullName -Force
            }
        }
    }
}
