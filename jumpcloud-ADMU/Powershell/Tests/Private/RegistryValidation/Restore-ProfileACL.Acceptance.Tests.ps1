Describe "Restore-ProfileACL Tests" -Tag "Acceptance" {
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

        # import the init user function:
        . "$helpFunctionDir\Initialize-TestUser.ps1"
    }

    Context "Restore ProfileACL Tests" {
        # Test Setup
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # Get the SID of the initialized user
            $userToMigrateFromSID = (Get-LocalUser -Name $userToMigrateFrom).SID.Value
            # define test case input
            $testCaseInput = @{
                JumpCloudUserName       = $userToMigrateTo
                SelectedUserName        = $userToMigrateFrom
                TempPassword            = $tempPassword
                LeaveDomain             = $false
                ForceReboot             = $false
                UpdateHomePath          = $false
                InstallJCAgent          = $false
                AutoBindJCUser          = $false
                BindAsAdmin             = $false
                SetDefaultWindowsUser   = $true
                AdminDebug              = $false
                # JumpCloudConnectKey     = $null
                # JumpCloudAPIKey         = $null
                # JumpCloudOrgID          = $null
                ValidateUserShellFolder = $true
            }
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }
        }
        It "Validates that Restore-ProfileACL restores ACLs successfully" {
            # Migrate the initialized user to the second username
            $migrationInput = @{
                JumpCloudUserName       = $userToMigrateTo
                SelectedUserName        = $userToMigrateFrom
                TempPassword            = $tempPassword
                LeaveDomain             = $false
                ForceReboot             = $false
                UpdateHomePath          = $false
                InstallJCAgent          = $false
                AutoBindJCUser          = $false
                BindAsAdmin             = $false
                SetDefaultWindowsUser   = $true
                AdminDebug              = $false
                # JumpCloudConnectKey     = $null
                # JumpCloudAPIKey         = $null
                # JumpCloudOrgID          = $null
                ValidateUserShellFolder = $true
            }

            { Start-Migration @migrationInput } | Should -Not -Throw

            # test Restore-ProfileACL
            $aclBackupDir = "C:\Users\$userToMigrateTo\AppData\Local\JumpCloudADMU"
            $aclBackupFiles = @()
            if (Test-Path -Path $aclBackupDir -PathType Container) {
                $aclBackupFiles = Get-ChildItem -Path $aclBackupDir -File | Where-Object { $_.Name -match $aclBackupPattern }
            }
            $latestAclBackupFile = $aclBackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $backupPath = Join-Path -Path $aclBackupDir -ChildPath $latestAclBackupFile.Name
            { Restore-ProfileACL -BackupPath $backupPath } | Should -Not -Throw
        }
    }
}