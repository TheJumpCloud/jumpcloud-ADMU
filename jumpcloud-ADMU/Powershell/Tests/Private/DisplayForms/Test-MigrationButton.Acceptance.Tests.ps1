Describe "Test-MigrationButton Acceptance Tests" -Tag "Acceptance" {
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

        # mock the wmi command
        Mock -CommandName 'Get-WmiObject' {
            $wmiReturn = @{
                "Domain"              = "mockDomain.org"
                "Manufacturer"        = "mockManufacturer"
                "Model"               = "mockModel"
                "Name"                = "mockSystemName"
                "PrimaryOwnerName"    = "mockUsername"
                "TotalPhysicalMemory" = "436880384"
            }
            return $wmiReturn
        }
    }
    BeforeEach {
        $btn_migrateProfile = @{
            IsEnabled = $false
        }
        # default case input, username, password, JumpCloudUsername specified
        $testCaseInput = @{
            tb_JumpCloudUserName   = @{Text = "steve" }
            tb_JumpCloudConnectKey = @{Password = $null }
            tb_tempPassword        = @{Text = "Temp!23" }
            lvProfileList          = @{SelectedItem = @{
                    Username = "bob"
                }
            }
            tb_JumpCloudAPIKey     = @{Password = $null }
            cb_installJCAgent      = @{IsChecked = $false }
            cb_autobindJCUser      = @{IsChecked = $false }
            # selectedOrgID          = $null
        }
    }
    Context 'The selection form should allow you to migrate' {
        It 'when a selected user, tempPassword, username are specified' {
            Test-MigrationButton @testCaseInput | Should -Be $true
            $btn_migrateProfile.IsEnabled | Should -Be $true
        }
        Context "Connect Key Validation" {
            It 'When a selected user, tempPassword, username, ConnectKey are specified' {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudConnectKey.Password = "1111111111111111111111111111111111111111"
                # checkbox for install JCAgent
                $testCaseInput.cb_installJCAgent.IsChecked = $true
                # should return true
                Test-MigrationButton @testCaseInput | Should -Be $true
                $btn_migrateProfile.IsEnabled | Should -Be $true
            }
        }
    }
    Context 'The selection form should NOT allow you to migrate' {
        Context "Connect Key Validation" {
            It 'When a selected user, tempPassword, username, a ConnectKey with a non-40 char string are specified' {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudConnectKey.Password = "asdf"
                # checkbox for install JCAgent
                $testCaseInput.cb_installJCAgent.IsChecked = $true
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It 'When a selected user, tempPassword, username, a ConnectKey with a null char string are specified' {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudConnectKey.Password = ""
                # checkbox for install JCAgent
                $testCaseInput.cb_installJCAgent.IsChecked = $true
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It 'When a selected user, tempPassword, username, a ConnectKey with a char string containing a space are specified' {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudConnectKey.Password = "11111111111111111111 1111111111111111111"
                # checkbox for install JCAgent
                $testCaseInput.cb_installJCAgent.IsChecked = $true
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
        }
        Context "Api Key Validation" {
            It 'When a selected user, tempPassword, username, a null API key are specified' {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudAPIKey.Password = ""
                # checkbox for install JCAgent
                $testCaseInput.cb_installJCAgent.IsChecked = $true
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a an invalid API key is specified" {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudAPIKey.Password = "1111111111111111111111111111111111111111"
                # checkbox for install JCAgent
                $testCaseInput.cb_autobindJCUser.IsChecked = $true
                # should return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a 'invalid' API key & 'orgID' are specified" {
                # add the selectedOrgID string to the test input
                $testCaseInput.Add(
                    'selectedOrgID', "111111111111111111111111"
                )
                # add input for connect Key
                $testCaseInput.tb_JumpCloudAPIKey.Password = "1111111111111111111111111111111111111111"
                # checkbox for install JCAgent
                $testCaseInput.cb_autobindJCUser.IsChecked = $true
                # should return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a 'valid' API key and an 'invalid' orgID are specified" {
                # add the selectedOrgID string to the test input
                $testCaseInput.Add(
                    'selectedOrgID', "1111111111"
                )
                # add input for connect Key
                $testCaseInput.tb_JumpCloudAPIKey.Password = "1111111111111111111111111111111111111111"
                # checkbox for install JCAgent
                $testCaseInput.cb_autobindJCUser.IsChecked = $true
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a real API key and is specified" {
                # add input for connect Key
                $testCaseInput.tb_JumpCloudAPIKey.Password = $env:PESTER_APIKEY
                # checkbox for install JCAgent
                $testCaseInput.cb_autobindJCUser.IsChecked = $true
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $true
                $btn_migrateProfile.IsEnabled | Should -Be $true
            }
        }
        Context "Temp Pass Validation" {
            It 'When a temp pass with a space is specified' {
                $testCaseInput.tb_tempPassword.Text = "has space"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It 'When a pass with a null string is specified' {
                $testCaseInput.tb_tempPassword.Text = ""
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
        }
        Context "Selected User Validation" {
            It "When a user is not selected" {
                $testCaseInput.lvProfileList.SelectedItem.Username = $null
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a user is local to the system" {
                $testCaseInput.lvProfileList.SelectedItem.Username = "mockSystemName\Someone"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a user is an unknown account" {
                $testCaseInput.lvProfileList.SelectedItem.Username = "UNKNOWN ACCOUNT"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
        }
        Context "JumpCloud Username Validation" {
            It "When a local user exists without a valid SID" {
                # This test requires a windows device to create the get the user
                $userName = "TesterUser1234"
                $password = "TesterPassword1234!!"
                $newUserPassword = ConvertTo-SecureString -String "$($Password)" -AsPlainText -Force
                New-localUser -Name "$($UserName)" -password $newUserPassword -Description "Created By JumpCloud ADMU"

                # validate that the user was created
                $localUsersWithoutSIDs = Get-LocalUser
                Write-Host "The following local users exist on the system"
                Write-Host $localUsersWithoutSIDs.Name
                $username | Should -BeIn $localUsersWithoutSIDs.Name

                # set the JumpCloud user to the new username
                $testCaseInput.tb_JumpCloudUserName.Text = $userName

                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a null string username is specified" {
                $testCaseInput.tb_JumpCloudUserName.Text = ""
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When a username with a space is specified" {
                $testCaseInput.tb_JumpCloudUserName.Text = "user name"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When username string with more than 20 chars is specified" {
                $testCaseInput.tb_JumpCloudUserName.Text = "veryLongUsernamesAreNotAllowed"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When the local username already exists on the system" {
                Mock 'Test-LocalUsername' { return $true }
                $testCaseInput.tb_JumpCloudUserName.Text = "userAlreadyExists"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
            It "When the username is the same as the system hostname" {
                $testCaseInput.tb_JumpCloudUserName.Text = "mockSystemName"
                # should not return true
                Test-MigrationButton @testCaseInput | Should -Be $false
                $btn_migrateProfile.IsEnabled | Should -Be $false
            }
        }
    }

    # Add more acceptance tests as needed
}
