Describe "Start-Reversion Tests" -Tag "Migration Parameters" {
    # Import Functions
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

    Context "Reversion Tests" {
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
        Context "Reversion Success" {
            It "Tests that the Reversion is successful and returns a valid result object" {

                #Pre Migration Access
                icacls "C:\Users\$userToMigrateFrom" /setowner $userToMigrateFrom /T /C /Q
                # Re-fetch the ACL after setting owner
                $preMigrationACL = Get-Acl -Path "C:\Users\$userToMigrateFrom"
                $preMigrationOwner = $preMigrationACL.Owner
                $preMigrationOwner | Should -Match $([System.Text.RegularExpressions.Regex]::Escape($userToMigrateFrom))


                { Start-Migration @testCaseInput } | Should -Not -Throw

                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }

                $revertResult = Start-Reversion @reversionInput -force
                Write-Host "Revert Result Object: $($revertResult | Out-String)"

                # Validate that the owner is the same as pre-migration
                $postReversionACL = Get-Acl -Path "C:\Users\$userToMigrateFrom"
                $postReversionOwner = $postReversionACL.Owner
                $postReversionOwner | Should -Be $preMigrationOwner

                $revertResult | Should -Not -BeNullOrEmpty
                Write-Host "Reversion Result: $($revertResult | Out-String)"
                # Verify High-Level Success
                $revertResult.Success | Should -BeTrue
                $revertResult.RegistryUpdated | Should -BeTrue
                $revertResult.Errors.Count | Should -Be 0

                # Verify Data Integrity
                $revertResult.UserSID | Should -Be $userToMigrateFromSID
                $revertResult.TargetProfilePath | Should -Be $reversionInput.TargetProfileImagePath

                $revertResult.FilesReverted.Count | Should -BeGreaterThan 0



                # 5. Validate that the original user exists (System Check)
                { Get-LocalUser -Name $userToMigrateFrom } | Should -Not -Throw
            }
        }
        Context "Reversion Failure" {
            It "Tests that the Reversion fails with an invalid SID" {

                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration with an invalid SID
                $reversionInput = @{
                    UserSID                = "S-1-5-21-0000000000-0000000000-0000000000-9999" # Invalid SID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }

                { Start-Reversion @reversionInput } | Should -Throw "Profile registry path not found for SID: S-1-5-21-0000000000-0000000000-0000000000-9999"
            }
            It "Tests that the Reversion fails with an invalid SID NO Profile Path param" {

                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration with an invalid SID
                $reversionInput = @{
                    UserSID = "S-1-5-21-0000000000-0000000000-0000000000-9999" # Invalid SID
                }

                { Start-Reversion @reversionInput } | Should -Throw "Profile registry path not found for SID: S-1-5-21-0000000000-0000000000-0000000000-9999"
            }

            It "Tests that the Reversion fails with a missing profile path" {

                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration with a missing profile path
                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\NonExistentProfile"
                }

                { Start-Reversion @reversionInput } | Should -Throw "Profile directory does not exist: C:\Users\NonExistentProfile"
            }

            # ACL Backup Missing Test Case
            It "Tests that the Reversion handles missing ACL backup file gracefully" {
                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration
                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }

                # Remove any existing ACL backup files to simulate missing backup
                $aclBackupDir = "C:\Users\$userToMigrateFrom\AppData\Local\JumpCloudADMU"
                if (Test-Path -Path $aclBackupDir) {
                    Remove-Item -Path $aclBackupDir -Recurse -Force
                }

                { Start-Reversion @reversionInput } | Should -Throw "No ACL backup files found in directory: $aclBackupDir for SID: $userToMigrateFromSID. Cannot proceed with revert."
            }
        }
    }
}