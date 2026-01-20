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
            $tempPassword = "Temp123!Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword -Reversion $true
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

                Write-Host "Reversion Input Parameters: $($reversionInput | Out-String)"

                $revertResult = Start-Reversion @reversionInput -ErrorAction SilentlyContinue -Force
                Write-Host "Revert Result Object: $($revertResult | Out-String)"

                # Validate that the owner is the same as pre-migration
                $postReversionACL = Get-Acl -Path "C:\Users\$userToMigrateFrom"

                # Force Get-Acl to return the SID explicitly (Avoiding name resolution issues)
                $postReversionOwnerSID = $postReversionACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

                Write-Host "Post-Reversion Owner SID: $postReversionOwnerSID" -ForegroundColor Blue

                # Compare the folder's owner SID to the known User SID
                $postReversionOwnerSID | Should -Be $userToMigrateFromSID

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

                { Get-LocalUser -Name $userToMigrateFrom } | Should -Not -Throw # Original User should exist
                { Get-LocalUser -Name $userToMigrateTo -ErrorAction Stop } | Should -Throw
            }

            It "Allows reversion when the registry profile key is renamed to .bak" {
                { Start-Migration @testCaseInput } | Should -Not -Throw

                $profileListRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                $originalKeyPath = Join-Path -Path $profileListRoot -ChildPath $userToMigrateFromSID
                $bakKeyName = "$userToMigrateFromSID.bak"
                $bakKeyPath = Join-Path -Path $profileListRoot -ChildPath $bakKeyName

                if (-not (Test-Path -Path $originalKeyPath)) {
                    throw "Test precondition failed: profile registry key not found for SID $userToMigrateFromSID"
                }

                if (Test-Path -Path $bakKeyPath) {
                    Remove-Item -Path $bakKeyPath -Recurse -Force
                }

                try {
                    Rename-Item -Path $originalKeyPath -NewName $bakKeyName -Force

                    $reversionInput = @{
                        UserSID                = $userToMigrateFromSID
                        TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                    }

                    $revertResult = Start-Reversion @reversionInput -ErrorAction Stop -Force
                    $revertResult | Should -Not -BeNullOrEmpty
                    $revertResult.Success | Should -BeTrue
                    $revertResult.RegistryUpdated | Should -BeTrue
                } finally {
                    if ((Test-Path -Path $bakKeyPath) -and -not (Test-Path -Path $originalKeyPath)) {
                        Rename-Item -Path $bakKeyPath -NewName $userToMigrateFromSID -Force
                    }
                }
            }
        }
        Context "Reversion Failure" {
            It "Tests that the Reversion fails with an invalid SID" {

                # Revert the migration with an invalid SID
                $reversionInput = @{
                    UserSID                = "S-1-5-21-0000000000-0000000000-0000000000-9999" # Invalid SID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }

                { Start-Reversion @reversionInput } | Should -Throw "UserSID provided could not be translated"
            }
            It "Tests that the Reversion fails with an Valid SID and an invalid profilePath" {

                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration with a valid SID and invalid profileImagePath
                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\InvalidProfilePath"
                }

                { Start-Reversion @reversionInput } | Should -Throw "Cannot validate argument on parameter 'TargetProfileImagePath'. Target profile path does not exist: C:\Users\InvalidProfilePath"
            }


            # ACL Backup Missing Test Case
            It "Tests that the Reversion handles missing ACL backup files" {
                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration
                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }

                # Remove any existing ACL backup files to simulate missing backup
                $aclBackupDir = "C:\Users\$userToMigrateFrom\AppData\Local\JumpCloudADMU"
                # List all the backup files before deletion for debugging
                Write-Host "Existing ACL Backup Files in $aclBackupDir before deletion:" -Foreground Yellow
                Get-ChildItem -Path $aclBackupDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Write-Host $_.FullName -Foreground Yellow
                }
                if (Test-Path -Path $aclBackupDir) {
                    Remove-Item -Path $aclBackupDir -Recurse -Force
                }
                { Start-Reversion @reversionInput -ErrorAction Stop -Force } | Should -Throw "*No ACL backup files found*"
            }

            # NTUser Backup Missing Test Case
            It "Tests that the Reversion handles missing NTUser backup files" {
                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw
                # Revert the migration
                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }
                # Remove any existing NTUser.DAT backup files to simulate missing backup
                # Ntuser backups should look like  NTUSER_original__Time
                $ntuserBackupPattern = "NTUSER_original_*"
                $userProfileDir = "C:\Users\$userToMigrateFrom"
                # Remove NTUser_Original_*.DAT backup
                Get-ChildItem -Path $userProfileDir -Filter $ntuserBackupPattern -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    Remove-Item -Path $_.FullName -Force
                }
                { Start-Reversion @reversionInput -Force -ErrorAction Stop } | Should -Throw "*No NTUser.DAT backup files found in directory*"
            }

            # UsrClass Backup Missing Test Case
            It "Tests that the Reversion handles missing UsrClass backup files" {
                # Migrate the initialized user to the second username
                { Start-Migration @testCaseInput } | Should -Not -Throw

                # Revert the migration
                $reversionInput = @{
                    UserSID                = $userToMigrateFromSID
                    TargetProfileImagePath = "C:\Users\$userToMigrateFrom"
                }

                # --- FIX STARTS HERE ---
                # Construct the correct path to UsrClass.dat
                $userProfileDir = "C:\Users\$userToMigrateFrom"
                $usrClassPath = Join-Path $userProfileDir "AppData\Local\Microsoft\Windows"

                $usrclassBackupPattern = "USRCLASS_original_*"

                # Verify path exists before trying to enumerate (optional safety)
                if (Test-Path $usrClassPath) {
                    # Remove UsrClass_Original_*.dat backup from the CORRECT location
                    Get-ChildItem -Path $usrClassPath -Filter $usrclassBackupPattern -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        Remove-Item -Path $_.FullName -Force
                    }
                }
                # --- FIX ENDS HERE ---

                { Start-Reversion @reversionInput -ErrorAction Stop -Force } | Should -Throw "*No UsrClass.dat backup files found in directory*"
            }

        }
    }
}