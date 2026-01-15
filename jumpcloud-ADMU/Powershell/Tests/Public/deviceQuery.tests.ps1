Describe "ADMU Device Query Script Tests" -Tag "InstallJC" {
    BeforeAll {
        # get the remote invoke script path
        $global:remoteInvoke = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\DeviceInit\DeviceQuery.ps1'
        if (-not (Test-Path $global:remoteInvoke)) {
            throw "TEST SETUP FAILED: Script not found at the calculated path: $($global:remoteInvoke). Please check the relative path in the BeforeAll block."
        }
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

        # import functions from the remote invoke script
        # get the function definitions from the script
        $scriptContent = Get-Content -Path $global:remoteInvoke -Raw
        $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)

        # set the matches.value to a temp file and import the functions
        $tempFunctionFile = Join-Path $PSScriptRoot 'deviceQueryFunctions.ps1'
        $functionMatches.Value | Set-Content -Path $tempFunctionFile -Force

        # import the functions from the temp file
        . $tempFunctionFile
    }

    It "The contents of the device query script should be under 32,767 character limit" {
        # Normalize line endings to LF to ensure consistent character count across platforms
        $measured = $scriptContent | Measure-Object -Character
        Write-Host "Character Count of Device Query Script: $($measured.Characters) | Limit: 32767"
        $measured.Characters | Should -BeLessThan 32767
    }
    Context "Get-System Tests" {
        It "Should get the system data" {
            Get-System -systemContextBinding $true | Should -Not -Be $null
        }

    }
    Context "Set-System Tests" {
        BeforeAll {
            # set the system description to null
            Set-System -prop "Description" -Payload ""
            # set the attributes to null
            # get existing attributes
            $systemData = Get-System -systemContextBinding $true
            $existingAttributes = $systemData.attributes
            if ($existingAttributes -ne $null) {

                foreach ($attr in $existingAttributes) {
                    Set-System -prop "Attributes" -Payload @{ "name" = $attr.name; "value" = $null }
                }
            }
        }
        It "Should set the system description" {
            $testDescription = "Test Description $(Get-Random)"
            Set-System -prop "Description" -Payload "$testDescription"
            $systemData = Get-System -systemContextBinding $true
            $retrievedDescription = $systemData.description | ConvertFrom-Json
            $retrievedDescription | Should -Be $testDescription
        }
        It "Should set the system description to empty string" {
            $testDescription = ""
            Set-System -prop "Description" -Payload "$testDescription"
            $systemData = Get-System -systemContextBinding $true
            $retrievedDescription = $systemData.description | ConvertFrom-Json
            $retrievedDescription | Should -Be $testDescription
        }
        It "Should set a system attribute when it does not exist" {
            $existingSystem = Get-System -systemContextBinding $true
            $attributeKey = "TestAttribute$(Get-Random)"
            $attributeValue = "TestValue$(Get-Random)"
            Set-System -prop "Attributes" -payload @{ "name" = "$attributeKey"; "value" = "$attributeValue" }
            $updatedSystem = Get-System -systemContextBinding $true
            $attribute = $updatedSystem.attributes | Where-Object { $_.name -eq $attributeKey }
            $attribute.value | Should -Be $attributeValue
        }
        It "Should set a system attribute when it does exist" {
            $existingSystem = Get-System -systemContextBinding $true
            $attributeKey = "TestAttribute$(Get-Random)"
            $attributeValue = "TestValue$(Get-Random)"
            # set the attribute first
            Set-System -prop "Attributes" -payload @{ "name" = "$attributeKey"; "value" = "$attributeValue" }
            # update the attribute
            $newAttributeValue = "UpdatedValue$(Get-Random)"
            Set-System -prop "Attributes" -payload @{ "name" = "$attributeKey"; "value" = "$newAttributeValue" }
            $updatedSystem = Get-System -systemContextBinding $true
            $attribute = $updatedSystem.attributes | Where-Object { $_.name -eq $attributeKey }
            $attribute.value | Should -Be $newAttributeValue
        }
        It "Should clear a system attribute if the payload string is null" {
            $existingSystem = Get-System -systemContextBinding $true
            $attributeKey = "TestAttribute$(Get-Random)"
            $attributeValue = "TestValue$(Get-Random)"
            # set the attribute first
            Set-System -prop "Attributes" -payload @{ "name" = "$attributeKey"; "value" = "$attributeValue" }
            # clear the attribute
            Set-System -prop "Attributes" -payload @{ "name" = "$attributeKey"; "value" = $null }
            $updatedSystem = Get-System -systemContextBinding $true
            $attribute = $updatedSystem.attributes | Where-Object { $_.name -eq $attributeKey }
            $attribute | Should -Be $null
        }
    }
    Context "Get-ADMUUser Tests" {
        It "Should return data when 'AD' users exist on a system" {
            # in get-ADMUUser there's a function to call jcosqueryi.exe to get the AD users. In CI this wont work so we will mock that function to return test data
            $admuUsers = Get-ADMUUser -localUsers
            $admuUsers | Should -Not -Be $null
            $admuUsers.Count | Should -BeGreaterThan 0

            foreach ($user in $admuUsers) {
                Write-Host "ADMU User with SID: $($user.sid) | localPath: $($user.localPath)"
            }
        }
        It "Data from Get-ADMUUser should have the required properties" {
            $admuUsers = Get-ADMUUser -localUsers
            $requiredProperties = @("st", "msg", "sid", "localPath", "un", "uid", "lastLogin")
            foreach ($user in $admuUsers) {
                $MemberProperties = $user | Get-Member
                foreach ($prop in $requiredProperties) {
                    $MemberProperties.Name | Should -Contain $prop
                }
            }
        }
        It "When some has been previously migrated, their status is set to 'complete'" {
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $tempPassword = "Temp123!Temp123!"
            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # set the user's profileImagePath in registry to simulate a previous migration
            $sid = (New-Object System.Security.Principal.NTAccount($userToMigrateFrom)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
            if (-not (Test-Path $regPath)) {
                throw "Test Setup Failed: Registry path $regPath does not exist for user $userToMigrateFrom"
            }
            # append .ADMU to the existing profileImagePath to simulate migration
            $existingProfilePath = (Get-ItemProperty -Path $regPath -Name "ProfileImagePath").ProfileImagePath
            $newProfilePath = "$existingProfilePath.ADMU"
            Set-ItemProperty -Path $regPath -Name "ProfileImagePath" -Value $newProfilePath
            # get ADMU users
            $admuUsers = Get-ADMUUser -localUsers
            $migratedUser = $admuUsers | Where-Object { $_.sid -eq $sid }
            $migratedUser | Should -Not -Be $null
            $migratedUser.st | Should -Be "Complete"
            $migratedUser.msg | Should -Be "User previously migrated"
        }
    }
    Context "Set-SystemDesc Tests" {
        BeforeEach {
            # set the system description to null before each test
            Set-System -prop "Description" -Payload ""
        }
        It "Data from Get-ADMUUser can be pushed to system description" {
            $admuUsers = Get-ADMUUser -localUsers
            $descResult = Set-SystemDesc -ADMUUsers $admuUsers
            # retrieve system description
            $systemData = Get-System -systemContextBinding $true
            $retrievedDescription = $systemData.description | ConvertFrom-Json
            foreach ($user in $admuUsers) {
                $foundUser = $retrievedDescription | Where-Object { $_.sid -eq $user.sid }
                $foundUser | Should -Not -Be $null
                $foundUser.un | Should -Be $user.un
                $foundUser.localPath | Should -Be $user.localPath
                $foundUser.msg | Should -Be $user.msg
                $foundUser.st | Should -Be $user.st
                $foundUser.uid | Should -Be $user.uid
            }
        }
        It "When a new user is added to the device, it's added to the system description" {
            $admuUsers = Get-ADMUUser -localUsers
            # add a new user to the list
            $newUserSID = "S-1-5-21-999999999-999999999-999999999-1001"
            $newUser = [PSCustomObject]@{
                sid       = $newUserSID
                un        = "NewTestUser"
                localPath = "C:/Users/NewTestUser"
                msg       = "Migration started"
                st        = "InProgress"
                uid       = $null
                lastLogin = $null
            }
            $admuUsers += $newUser
            # push to system description
            $descResult = Set-SystemDesc -ADMUUsers $admuUsers
            # retrieve system description
            $systemData = Get-System -systemContextBinding $true
            $retrievedDescription = $systemData.description | ConvertFrom-Json
            $foundUser = $retrievedDescription | Where-Object { $_.sid -eq $newUserSID }
            $foundUser | Should -Not -Be $null
            $foundUser.un | Should -Be $newUser.un
            $foundUser.localPath | Should -Be $newUser.localPath
            $foundUser.msg | Should -Be $newUser.msg
            $foundUser.st | Should -Be $newUser.st
            $foundUser.uid | Should -Be $newUser.uid
        }
        It "Should return 'Pending' when there are only pending users" {
            # Create users with only Pending state
            $testUsers = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-1111111111-1111111111-1111111111-1001"
                    localPath = "C:\Users\User1"
                    un        = "User1"
                    uid       = ""
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-2222222222-2222222222-2222222222-1002"
                    localPath = "C:\Users\User2"
                    un        = "User2"
                    uid       = ""
                    lastLogin = $null
                }
            )
            $descResult = Set-SystemDesc -ADMUUsers $testUsers
            $descResult.Status | Should -Be "Pending"
            # Verify the attribute was set
            $systemData = Get-System -systemContextBinding $true
            $admuAttr = $systemData.attributes | Where-Object { $_.name -eq "admu" }
            $admuAttr.value | Should -Be "Pending"
        }

        It "Should return 'InProgress' when there are pending users and users with other states (not Error/Pending/Complete/Skip)" {
            # Create users with Pending and custom states
            $testUsers = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-3333333333-3333333333-3333333333-1003"
                    localPath = "C:\Users\User3"
                    un        = "User3"
                    uid       = ""
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'InProgress'
                    msg       = 'Migrating'
                    sid       = "S-1-5-21-4444444444-4444444444-4444444444-1004"
                    localPath = "C:\Users\User4"
                    un        = "User4"
                    uid       = ""
                    lastLogin = $null
                }
            )
            $descResult = Set-SystemDesc -ADMUUsers $testUsers
            $descResult.Status | Should -Be "InProgress"
            # Verify the attribute was set
            $systemData = Get-System -systemContextBinding $true
            $admuAttr = $systemData.attributes | Where-Object { $_.name -eq "admu" }
            $admuAttr.value | Should -Be "InProgress"
        }

        It "Should return 'Error' when there are pending users and error state users" {
            # Create users with Pending and Error states
            $testUsers = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-5555555555-5555555555-5555555555-1005"
                    localPath = "C:\Users\User5"
                    un        = "User5"
                    uid       = ""
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Error'
                    msg       = 'Migration failed'
                    sid       = "S-1-5-21-6666666666-6666666666-6666666666-1006"
                    localPath = "C:\Users\User6"
                    un        = "User6"
                    uid       = ""
                    lastLogin = $null
                }
            )
            $descResult = Set-SystemDesc -ADMUUsers $testUsers
            $descResult.Status | Should -Be "Error"
            # Verify the attribute was set
            $systemData = Get-System -systemContextBinding $true
            $admuAttr = $systemData.attributes | Where-Object { $_.name -eq "admu" }
            $admuAttr.value | Should -Be "Error"
        }

        It "Should return 'Pending' when there is a mix of pending, complete, and skip states" {
            # Create users with Pending, Complete, and Skip states
            $testUsers = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-7777777777-7777777777-7777777777-1007"
                    localPath = "C:\Users\User7"
                    un        = "User7"
                    uid       = ""
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Complete'
                    msg       = 'Migration completed'
                    sid       = "S-1-5-21-8888888888-8888888888-8888888888-1008"
                    localPath = "C:\Users\User8"
                    un        = "User8"
                    uid       = ""
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Skipped'
                    sid       = "S-1-5-21-9999999999-9999999999-9999999999-1009"
                    localPath = "C:\Users\User9"
                    un        = "User9"
                    uid       = ""
                    lastLogin = $null
                }
            )
            $descResult = Set-SystemDesc -ADMUUsers $testUsers
            $descResult.Status | Should -Be "Pending"
            # Verify the attribute was set
            $systemData = Get-System -systemContextBinding $true
            $admuAttr = $systemData.attributes | Where-Object { $_.name -eq "admu" }
            $admuAttr.value | Should -Be "Pending"
        }

        It "Should return 'Complete' when all users are complete or skip (no pending or error)" {
            # Create users with only Complete and Skip states
            $testUsers = @(
                [PSCustomObject]@{
                    st        = 'Complete'
                    msg       = 'Migration completed'
                    sid       = "S-1-5-21-1010101010-1010101010-1010101010-1010"
                    localPath = "C:\Users\User10"
                    un        = "User10"
                    uid       = ""
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Skipped'
                    sid       = "S-1-5-21-1111111111-2222222222-3333333333-1011"
                    localPath = "C:\Users\User11"
                    un        = "User11"
                    uid       = ""
                    lastLogin = $null
                }
            )
            $descResult = Set-SystemDesc -ADMUUsers $testUsers
            $descResult.Status | Should -Be "Complete"
            # Verify the attribute was set
            $systemData = Get-System -systemContextBinding $true
            $admuAttr = $systemData.attributes | Where-Object { $_.name -eq "admu" }
            $admuAttr.value | Should -Be "Complete"
        }
        It "When the Set-Desc runs twice and no updates are made, the system description remains the same" {
            $admuUsers = Get-ADMUUser -localUsers
            $descResult1 = Set-SystemDesc -ADMUUsers $admuUsers
            Start-Sleep -Seconds 2
            $descResult2 = Set-SystemDesc -ADMUUsers $admuUsers
            $descResult1.Description | Should -Be $descResult2.Description
        }
        It "When the Set-Desc runs twice and updates are made, the system description is updated" {
            $admuUsers = Get-ADMUUser -localUsers
            $descResult1 = Set-SystemDesc -ADMUUsers $admuUsers
            # modify one user's status
            $admuUsers[0].st = "Complete"
            $admuUsers[0].msg = "User previously migrated"
            Start-Sleep -Seconds 2
            $descResult2 = Set-SystemDesc -ADMUUsers $admuUsers
            $systemAfter = Get-System -systemContextBinding $true
            $foundUser = ($systemAfter.Description | ConvertFrom-Json) | Where-Object { $_.sid -eq $admuUsers[0].sid }
            $foundUser.st | Should -Be "Complete"
            $foundUser.msg | Should -Be "User previously migrated"
        }
    }
}