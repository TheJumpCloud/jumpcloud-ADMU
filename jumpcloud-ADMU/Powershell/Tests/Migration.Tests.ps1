function Enable-TestNameAsVariablePlugin {
    & (get-module pester) {
        $PluginParams = @{
            Name               = "SaveTestNameToVariable"
            EachTestSetupStart = {
                $GLOBAL:TestName = $Context.Test.Name
            }
            EachTestTeardown   = {
                $GLOBAL:TestName = $null
            }
        }
        $state.Plugin += New-PluginObject @PluginParams
    }
}
# Add test name as variable
# https://github.com/pester/Pester/issues/1611
BeforeAll {
    # import build variables for test cases
    write-host "Importing Build Variables:"
    . $PSScriptRoot\BuildVariables.ps1
    # import functions from start migration
    write-host "Importing Start-Migration Script:"
    . $PSScriptRoot\..\Start-Migration.ps1
    # setup tests (This creates any of the users in the build vars dictionary)
    write-host "Running SetupAgent Script:"
    . $PSScriptRoot\SetupAgent.ps1
    # For each user in testing hash, create new user with the specified password and init the account
    forEach ($User in $userTestingHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }
    ForEach ($User in $JCFunctionalHash.Values) {
        InitUser -UserName $($User.Username) -Password $($User.Password)
    }

    $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
    $regex = 'systemKey\":\"(\w+)\"'
    $systemKey = [regex]::Match($config, $regex).Groups[1].Value

    # Remove users with ADMU_ prefix
    # Remove Created Users
    Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
}
Describe 'Migration Test Scenarios' {
    Enable-TestNameAsVariablePlugin
    BeforeEach {
        Write-Host "---------------------------"
        Write-Host "Begin Test: $testName`n"
    }
    Context 'Start-Migration on local accounts (Test Functionallity)' {
        It "username extists for testing" {
            foreach ($user in $userTestingHash.Values) {
                $user.username | Should -Not -BeNullOrEmpty
                $user.JCusername | Should -Not -BeNullOrEmpty
                Get-LocalUser $user.username | Should -Not -BeNullOrEmpty
            }
        }

        It "Test Convert profile migration for Local users" {
            foreach ($user in $userTestingHash.Values) {
                # Remove log before testing
                $logPath = "C:\Windows\Temp\jcadmu.log"
                if (Test-Path -Path $logPath) {
                    Remove-Item $logPath
                    New-Item $logPath -Force -ItemType File
                }

                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
                # Begin Test
                { Start-Migration -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath } | Should -Not -Throw
                # Depending on the user in the UserTestingHash, the home path will differ
                if ($user.UpdateHomePath) {
                    $UserHome = "C:\Users\$($user.JCUsername)"
                } else {
                    $UserHome = "C:\Users\$($user.Username)"
                }
                # Read the log and get date data
                $log = "C:\Windows\Temp\jcadmu.log"
                $regex = [regex]"ntuser_original_([0-9]+-[0-9]+-[0-9]+-[0-9]+[0-9]+[0-9]+)"
                $match = Select-String -Path:($log) -Pattern:($regex)
                # Get the date appended to the backup registry files:
                $dateMatch = $match.Matches.Groups[1].Value
                # For testing write out the date
                # Write-Host "SEARCHING FOR : $dateMatch in $UserHome"
                # User Home Directory Should Exist
                Test-Path "$UserHome" | Should -Be $true
                # Backup Registry & Registry Files Should Exist
                # Timestamp from log should exist on registry backup files
                Test-Path "$UserHome/NTUSER_original_$dateMatch.DAT" | Should -Be $true
                Test-Path "$UserHome/NTUSER.DAT" | Should -Be $true
                Test-Path "$UserHome/AppData/Local/Microsoft/Windows/UsrClass.DAT" | Should -Be $true
                Test-Path "$UserHome/AppData/Local/Microsoft/Windows/UsrClass_original_$dateMatch.DAT" | Should -Be $true

            }
        }

        It "Test UWP_JCADMU was downloaded & exists" {
            Test-Path "C:\Windows\uwp_jcadmu.exe" | Should -Be $true
        }
        It "Account of a prior migration can be sucessfully migrated again and not overwrite registry backup files" {
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user3 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $user1 -Password $Password
            # Migrate the initialized user to the second username
            { Start-Migration -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$user1" -TempPassword "$($Password)" } | Should -Not -Throw
            # Migrate the migrated account to the third username
            { Start-Migration -AutobindJCUser $false -JumpCloudUserName $user3 -SelectedUserName "$ENV:COMPUTERNAME\$user2" -TempPassword "$($Password)" } | Should -Not -Throw
            # The original user1 home directory should exist
            "C:\Users\$user1" | Should -Exist
            # The original user1 home directory should exist
            "C:\Users\$user2" | Should -Not -Exist
            # The original user1 home directory should exist
            "C:\Users\$user3" | Should -Not -Exist
            # This user should contain two backup files.
            (Get-ChildItem "C:\Users\$user1" -Hidden | Where-Object { $_.Name -match "NTUSER_original" }).Count | Should -Be 2
            (Get-ChildItem "C:\Users\$user1\AppData\Local\Microsoft\Windows\" -Hidden | Where-Object { $_.Name -match "UsrClass_original" }).Count | Should -Be 2

        }
        It "Start-Migration should throw if the jumpcloud user already exists & not migrate anything" {
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            InitUser -UserName $user1 -Password $Password
            InitUser -UserName $user2 -Password $Password

            # attempt to migrate to user from previous step
            { Start-Migration -JumpCloudAPIKey $env:PESTER_APIKEY -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$user1" -TempPassword "$($Password)" } | Should -Throw
            # The original user should exist
            "C:\Users\$user1" | Should -Exist
            # The user we are migrating to existed before the test, it should also exist after
            "C:\Users\$user2" | Should -Exist
        }
    }

    Context 'Start-Migration Sucessfully Binds JumpCloud User to System' {
        It 'user bound to system after migration' {
            $headers = @{}
            $headers.Add("x-org-id", $env:PESTER_ORGID)
            $headers.Add("x-api-key", $env:PESTER_APIKEY)
            $headers.Add("content-type", "application/json")

            foreach ($user in $JCFunctionalHash.Values) {
                Write-Host "`n## Begin Bind User Test ##"
                Write-Host "## $($user.Username) Bound as Admin: $($user.BindAsAdmin)  ##`n"
                $users = Get-JCSDKUser
                if ("$($user.JCUsername)" -in $users.Username) {
                    $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                    Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                    Remove-JcSdkUser -Id $existing.Id
                }

                $GeneratedUser = New-JcSdkUser -Email:("$($user.JCUsername)@jumpcloudadmu.com") -Username:("$($user.JCUsername)") -Password:("$($user.password)")
                if ($user.JCSystemUsername) {
                    $Body = @{"systemUsername" = $user.JCSystemUsername } | ConvertTo-Json
                    $updateSystemUsername = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systemusers/$($GeneratedUser.id)" -Method PUT -Headers $headers -Body $Body
                    Write-Host "Updated System Username to $($updateSystemUsername)"
                }

                Write-Host "`n## GeneratedUser ID: $($generatedUser.id)"
                Write-Host "## GeneratedUser Username: $($generatedUser.Username)`n"
                write-host "`nRunning: Start-Migration -JumpCloudUserName $($user.JCUsername) -SelectedUserName $($user.username) -TempPassword $($user.password)`n"
                { Start-Migration -JumpCloudAPIKey $env:PESTER_APIKEY -AutobindJCUser $true -JumpCloudUserName "$($user.JCUsername)" -SelectedUserName "$ENV:COMPUTERNAME\$($user.username)" -TempPassword "$($user.password)" -UpdateHomePath $user.UpdateHomePath -BindAsAdmin $user.BindAsAdmin } | Should -Not -Throw
                $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }

                Write-Host "`n## Validating sudo status on $($GeneratedUser.Id) | Should be ($($user.BindAsAdmin)) on $systemKey"
                $association | Should -not -BeNullOrEmpty

                if ($($user.BindAsAdmin)) {
                    Write-Host "UserID $($GeneratedUser.Id) should be sudo"
                    $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $true
                } else {
                    Write-Host "UserID $($GeneratedUser.Id) should be standard"
                    $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $null
                }

                if ($user.JCSystemUsername) {
                    Get-LocalUser | Where-Object { $_.Name -eq $user.JCSystemUsername } | Should -Not -BeNullOrEmpty
                }
            }
        }
    }
    Context 'Start-Migration Fails to Bind JumpCloud User to System and throws error' {
        It 'user bound to system after migration' {
            Write-Host "`nBegin Test: Start-Migration Fails to Bind JumpCloud User to System and throws error"
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            InitUser -UserName $user1 -Password $Password
            write-host "`nRunning: Start-Migration -JumpCloudUserName $($user2) -SelectedUserName $($user1) -TempPassword $($Password)`n"
            { Start-Migration -JumpCloudAPIKey $env:PESTER_APIKEY -AutobindJCUser $true -JumpCloudUserName "$($user2)" -SelectedUserName "$ENV:COMPUTERNAME\$($user1)" -TempPassword "$($Password)" } | Should -Throw
        }
    }
    AfterEach {
        Write-Host "`nEnd Test: $testName"
        Write-Host "---------------------------`n"
    }
}

AfterAll {
    $systems = Get-JCsdkSystem
    $CIsystems = $systems | Where-Object { $_.displayname -match "fv-az*" }
    foreach ($system in $CIsystems) {
        Remove-JcSdkSystem -id $system.Id
    }
}