Describe "Confirm-ProfileSidAssociation Acceptance Tests" -Tag "Migration Parameters" {
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

    Context "Confirm-ProfileSidAssociation Tests" {
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
        Context "Confirm-ProfileSidAssociation Successful Validation" {
            It "Tests that the Reversion is successful and returns a valid result object" {
                { Start-Migration @testCaseInput } | Should -Not -Throw
                $profileImagePath = "C:\Users\$userToMigrateFrom"
                $validationResult = Confirm-ProfileSidAssociation -ProfilePath $profileImagePath -UserSID $userToMigrateFromSID
                $validationResult.IsValid | Should -Be $true
            }
        }

        Context "Confirm-ProfileSidAssociation Failed Validation using mismatched ProfilePath" {
            It "Tests that the validation fails for mismatched profile path and SID" {
                { Start-Migration @testCaseInput } | Should -Not -Throw
                $profileImagePath = "C:\Users\SomeOtherUser"
                $validationResult = Confirm-ProfileSidAssociation -ProfilePath $profileImagePath -UserSID $userToMigrateFromSID
                $validationResult.IsValid | Should -Be $false
            }
        }
    }

}