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

    Context "Restore ProfileACL Migration tests" {
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

            # Get the C:\Users\UserToMigrateFrom ACL owner and access before migration
            $preMigrationACL = Get-Acl -Path "C:\Users\$userToMigrateFrom"
            $preMigrationOwner = $preMigrationACL.Owner
            $preMigrationOwner | Should -Contain $userToMigrateFrom

            $preMigrationAccess = $preMigrationACL.Access
            $TargetIdentity = $preMigrationOwner
            $ExpectedRights = "FullControl"

            $TargetAce = $preMigrationAccess | Where-Object {
                $_.IdentityReference -eq $TargetIdentity
            }
            $TargetAce.FileSystemRights | Should -Contain $ExpectedRights


            { Start-Migration @migrationInput } | Should -Not -Throw
            # Post Migration ACL check
            $postMigrationACL = Get-Acl -Path "C:\Users\$userToMigrateFrom"
            $postMigrationOwner = $postMigrationACL.Owner
            $postMigrationOwner | Should -Not -Contain $userToMigrateFrom
            $postMigrationOwner | Should -Contain $userToMigrateTo

            $TargetIdentity = $postMigrationOwner
            $ExpectedRights = "FullControl"

            $TargetAce = $preMigrationAccess | Where-Object {
                $_.IdentityReference -eq $TargetIdentity
            }
            $TargetAce.FileSystemRights | Should -Contain $ExpectedRights



            # test Restore-ProfileACL
            $aclBackupDir = "C:\Users\$userToMigrateFrom\AppData\Local\JumpCloudADMU"
            $aclBackupFiles = @()
            $UserSid = (Get-LocalUser -Name $userToMigrateFrom).SID.Value
            $aclBackupPattern = "^{0}_permission_backup_\d{{8}}-\d{{4}}$" -f [Regex]::Escape($UserSID)
            if (Test-Path -Path $aclBackupDir -PathType Container) {
                $aclBackupFiles = Get-ChildItem -Path $aclBackupDir -File | Where-Object { $_.Name -match $aclBackupPattern }
            }
            $latestAclBackupFile = $aclBackupFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $latestAclBackupFile | Should -Not -BeNullOrEmpty
            $backupPath = Join-Path -Path $aclBackupDir -ChildPath $latestAclBackupFile.Name
            { Restore-ProfileACL -BackupPath $backupPath } | Should -Not -Throw

            # Post Restore ACL check
            $restoredACL = Get-Acl -Path "C:\Users\$userToMigrateFrom"
            $restoredOwner = $restoredACL.Owner
            $restoredOwner | Should -Contain $userToMigrateFrom
            $restoredOwner | Should -Not -Contain $userToMigrateTo
            $TargetIdentity = $restoredOwner
            $ExpectedRights = "FullControl"
            $TargetAce = $restoredACL.Access | Where-Object {
                $_.IdentityReference -eq $TargetIdentity
            }
            $TargetAce.FileSystemRights | Should -Contain $ExpectedRights
        }
    }
    Context "Execution Logic" {
        BeforeEach {
            Mock Test-Path { return $true }
            Mock Write-ToLog
        }

        It "Should call icacls with the correct parameters" {
            # Mock icacls execution
            Mock icacls { return "Successfully processed 1 files" }

            $testBackup = "C:\Temp\perms.acl"
            Restore-ProfileACL -BackupPath $testBackup

            # Verify exact command arguments
            Assert-MockCalled icacls -Times 1 -ParameterFilter {
                $args[0] -eq "C:\Users\" -and
                $args[1] -eq "/restore" -and
                $args[2] -eq $testBackup -and
                $args[3] -eq "/T" -and
                $args[4] -eq "/C"
            }
        }

        It "Should log success when icacls returns exit code 0" {
            Mock icacls { return "Success" }

            # Force global success
            $global:LASTEXITCODE = 0

            Restore-ProfileACL -BackupPath "C:\Temp\backup"

            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq "Verbose" -and $Message -eq "Restore operation completed."
            }
        }

        It "Should log warning when icacls returns non-zero exit code" {
            # Simulate External Command Failure
            # Note: Modifying LastExitCode inside a mock can be tricky in some Pester scopes,
            # but setting the expectation for the code flow is key.
            # We force the variable immediately before the check would happen in a real scenario.
            Mock icacls { $global:LASTEXITCODE = 5; return "Fail" }

            Restore-ProfileACL -BackupPath "C:\Temp\backup"

            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq "Verbose" -and $Message -match "Warning: icacls save operation had issues"
            }
        }
    }
    Context "Path Validation" {

        It "Should abort and log error if BackupPath does not exist" {
            Mock Test-Path { return $false } -ParameterFilter { $Path -eq "C:\Fake\backup.acl" }
            Mock Write-ToLog
            Mock icacls

            Restore-ProfileACL -BackupPath "C:\Fake\backup.acl"

            # Verify icacls is NEVER called
            Assert-MockCalled icacls -Times 0

            # Verify Error was logged
            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq "Error" -and $Message -match "specified backup file was not found"
            }
        }

        It "Should abort and log warning if TargetPath (C:\Users\) does not exist" {
            Mock Test-Path {
                if ($Path -eq "C:\Valid\backup.acl") { return $true }
                if ($Path -eq "C:\Users\") { return $false }
            }
            Mock Write-ToLog
            Mock icacls

            Restore-ProfileACL -BackupPath "C:\Valid\backup.acl"

            # Verify icacls is NEVER called
            Assert-MockCalled icacls -Times 0

            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq "Warning" -and $Message -match "target directory was not found"
            }
        }


    }
    Context "Exception Handling" {
        It "Should catch exceptions thrown by command execution" {
            Mock Test-Path { return $true }
            Mock Write-ToLog

            # Make icacls throw a terminating error
            Mock icacls { throw "Critical Access Denied" }

            Restore-ProfileACL -BackupPath "C:\Temp\permissionsACL"

            # Check if the Catch block's log message was triggered
            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq "Warning" -and $Message -match "An error occurred during the icacls execution"
            }
        }
    }
}