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
        # Get the function definitions from the script
        $scriptContent = Get-Content -Path $global:remoteInvoke -Raw
        $pattern = '\#region functionDefinitions[\s\S]*\#endregion functionDefinitions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)

        # We replace 'exit 1' with a Throw.
        # This allows Pester to catch the failure without crashing the test runner.
        $sanitizedFunctions = $functionMatches.Value -replace 'exit 1', 'throw "EXIT_CALLED"'

        # Write the sanitized version to a temp file for testing
        $tempFunctionFile = Join-Path $PSScriptRoot 'deviceQueryFunctions.ps1'
        $sanitizedFunctions | Set-Content -Path $tempFunctionFile -Force

        # Import the SAFE functions
        . $tempFunctionFile
    }

    It "The contents of the device query script should be under 32,767 character limit" -Skip {
        # No longer necessary with changes to JumpCloud Agent
        # Normalize line endings to LF to ensure consistent character count across platforms
        $measured = $scriptContent | Measure-Object -Character
        Write-Host "Character Count of Device Query Script: $($measured.Characters) | Limit: 32767"
        $measured.Characters | Should -BeLessThan 32767
    }

    Context "API Key Functionality" {
        It "Set-System: System Context when JCApiKey is NOT provided" {
            Mock Get-Content -MockWith { return 'systemKey":"mockKey";"agentServerHost":"agent.jumpcloud.com"' }

            Mock Test-Path -MockWith { return $true }

            # This mimics the static method the script calls: [RSAEncryption.RSAEncryptionProvider]::GetRSAProviderFromPemFile($privKey)
            if (-not ([System.Management.Automation.PSTypeName]'RSAEncryption.RSAEncryptionProvider').Type) {
                Add-Type -TypeDefinition @"
                    namespace RSAEncryption {
                        public class RSAEncryptionProvider {
                            public static System.Security.Cryptography.RSACryptoServiceProvider GetRSAProviderFromPemFile(string s, object p) {
                                return new System.Security.Cryptography.RSACryptoServiceProvider();
                            }
                        }
                    }
"@
            }

            Mock Invoke-RestMethod -MockWith { return $true } -ParameterFilter {
                $Headers.ContainsKey("Authorization") -and $Headers["Authorization"] -match "Signature keyId="
            }

            Set-System -prop "Description" -Payload "TestPayload"

            Assert-MockCalled Invoke-RestMethod -Times 1
        }
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
            # Schema includes admin-curated fields (st/msg/sid/localPath/un/uid)
            # AND discovery-observed fields (lastLogin/lastWrite/lastLoginValid/profileSize).
            $requiredProperties = @("st", "msg", "sid", "localPath", "un", "uid", "lastLogin", "lastWrite", "lastLoginValid", "profileSize")
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
        It "Should default DefaultUserState to 'Auto' when parameter is omitted (fresh users get Pending or Skip)" {
            $admuUsers = Get-ADMUUser -localUsers
            $admuUsers | Should -Not -Be $null
            $freshUsers = $admuUsers | Where-Object { $_.st -ne 'Complete' }
            foreach ($user in $freshUsers) {
                $user.st | Should -BeIn @('Pending', 'Skip')
            }
        }
        It "Should mark all fresh users as 'Pending' when -DefaultUserState 'Pending' is specified" {
            $admuUsers = Get-ADMUUser -localUsers -DefaultUserState 'Pending'
            $admuUsers | Should -Not -Be $null
            $freshUsers = $admuUsers | Where-Object { $_.st -ne 'Complete' }
            $freshUsers.Count | Should -BeGreaterThan 0
            foreach ($user in $freshUsers) {
                $user.st | Should -Be 'Pending'
                $user.msg | Should -Be 'Planned'
            }
        }
        It "Should mark all fresh users as 'Skip' with the multi-user msg when -DefaultUserState 'Skip' is specified" {
            $admuUsers = Get-ADMUUser -localUsers -DefaultUserState 'Skip'
            $admuUsers | Should -Not -Be $null
            $freshUsers = $admuUsers | Where-Object { $_.st -ne 'Complete' }
            $freshUsers.Count | Should -BeGreaterThan 0
            foreach ($user in $freshUsers) {
                $user.st | Should -Be 'Skip'
                $user.msg | Should -Be 'Multiple AD users found; awaiting admin selection'
            }
        }
        It "Should reject -DefaultUserState values outside the validated set" {
            { Get-ADMUUser -localUsers -DefaultUserState 'Bogus' } | Should -Throw
        }
        It "In Auto mode with multiple fresh users on the device, fresh users should be marked 'Skip'" {
            # Create a second test user so the device has >1 fresh AD candidate
            $testUser1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $testUser2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $tempPassword = "Temp123!Temp123!"
            Initialize-TestUser -username $testUser1 -password $tempPassword
            Initialize-TestUser -username $testUser2 -password $tempPassword

            $admuUsers = Get-ADMUUser -localUsers -DefaultUserState 'Auto'
            $admuUsers | Should -Not -Be $null
            $freshUsers = @($admuUsers | Where-Object { $_.st -ne 'Complete' })
            # Sanity: confirm Auto resolved to Skip when fresh count > 1
            $freshUsers.Count | Should -BeGreaterThan 1
            foreach ($user in $freshUsers) {
                $user.st | Should -Be 'Skip'
                $user.msg | Should -Be 'Multiple AD users found; awaiting admin selection'
            }
        }
        It "Should populate lastWrite from NTUSER.DAT mtime as an ISO-8601 UTC string" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            $admuUsers = Get-ADMUUser -localUsers
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            # Freshly initialized profile has NTUSER.DAT, so lastWrite must be set
            # and must be a parseable timestamp.
            $found.lastWrite | Should -Not -BeNullOrEmpty
            { [DateTime]::Parse($found.lastWrite) } | Should -Not -Throw
        }
        It "Should populate profileSize as a non-negative numeric (GB) for discovered users" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            $admuUsers = Get-ADMUUser -localUsers
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -Not -BeNullOrEmpty
            # Get-ADMUUser returns [Math]::Round(... / 1GB, 2) which yields [double].
            $found.profileSize | Should -BeOfType [double]
            $found.profileSize | Should -BeGreaterOrEqual 0
        }
        It "Should set lastLoginValid based on lastLogin/lastWrite agreement (within 24h => true)" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            $admuUsers = Get-ADMUUser -localUsers
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            # For a freshly-created profile, NTUSER.DAT mtime and Win32 LastUseTime
            # are both stamped at initialization and should agree well within 24h.
            # If either is unexpectedly missing the contract is: lastLoginValid = $null.
            if ($found.lastLogin -and $found.lastWrite) {
                $found.lastLoginValid | Should -Be $true
            } else {
                $found.lastLoginValid | Should -Be $null
            }
        }
        It "Should reuse cached profileSize from -ExistingEntries when SID and localPath match" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $localPath = "C:\Users\$testUser"

            # Sentinel value clearly not a real profile size - if the result has
            # this exact value, we know the cache was reused (not recomputed).
            $cachedSentinel = 99.99
            $existingEntries = @(
                [PSCustomObject]@{
                    sid         = $sid
                    localPath   = $localPath
                    profileSize = $cachedSentinel
                }
            )

            $admuUsers = Get-ADMUUser -localUsers -ExistingEntries $existingEntries
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -Be $cachedSentinel
        }
        It "Should recompute profileSize when -ExistingEntries has a different localPath for the same SID" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            # Cache says profile lives at a different path than what discovery
            # finds - the cache must be invalidated and the size recomputed.
            $cachedSentinel = 99.99
            $existingEntries = @(
                [PSCustomObject]@{
                    sid         = $sid
                    localPath   = "C:\Users\StalePath_DoesNotMatch"
                    profileSize = $cachedSentinel
                }
            )

            $admuUsers = Get-ADMUUser -localUsers -ExistingEntries $existingEntries
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -Not -Be $cachedSentinel
        }
        It "Should recompute profileSize when -ExistingEntries cache has profileSize = `$null" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $localPath = "C:\Users\$testUser"

            # Existing entry exists for this SID but profileSize is $null, e.g.
            # legacy entry written by Build-MigrationDescription before DeviceQuery
            # has measured the profile. Cache must be ignored and value computed.
            $existingEntries = @(
                [PSCustomObject]@{
                    sid         = $sid
                    localPath   = $localPath
                    profileSize = $null
                }
            )

            $admuUsers = Get-ADMUUser -localUsers -ExistingEntries $existingEntries
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -BeOfType [double]
        }
        It "Should compute profileSize freshly when -ExistingEntries is `$null (first-run case)" {
            $testUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Initialize-TestUser -username $testUser -password "Temp123!Temp123!"
            $sid = (New-Object System.Security.Principal.NTAccount($testUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            $admuUsers = Get-ADMUUser -localUsers -ExistingEntries $null
            $found = $admuUsers | Where-Object { $_.sid -eq $sid }
            $found | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -Not -BeNullOrEmpty
            $found.profileSize | Should -BeOfType [double]
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
        It "Should return 'Pending' when ALL users are Skip and zero are Complete (awaiting admin selection)" {
            # Multi-user device discovered in Auto mode: every fresh user is Skip,
            # nothing is Complete. The device-level rollup must report 'Pending'
            # so admins can see it still needs attention.
            $testUsers = @(
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-allskip-001-001-001-1001"
                    localPath = "C:\Users\AllSkip1"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-allskip-002-002-002-1002"
                    localPath = "C:\Users\AllSkip2"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-allskip-003-003-003-1003"
                    localPath = "C:\Users\AllSkip3"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            $descResult = Set-SystemDesc -ADMUUsers $testUsers
            $descResult.Status | Should -Be "Pending"
            $systemData = Get-System -systemContextBinding $true
            $admuAttr = $systemData.attributes | Where-Object { $_.name -eq "admu" }
            $admuAttr.value | Should -Be "Pending"
        }
        It "Should preserve Skip users in the description across subsequent Set-SystemDesc calls" {
            # Skip users used to be stripped on merge. Now they must persist so
            # an admin can later flip one of them to Pending.
            $initialUsers = @(
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-persist-001-001-001-1001"
                    localPath = "C:\Users\Persist1"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-persist-002-002-002-1002"
                    localPath = "C:\Users\Persist2"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $initialUsers | Out-Null
            # Second discovery pass returns the same Skip users
            Set-SystemDesc -ADMUUsers $initialUsers | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = @($systemData.description | ConvertFrom-Json)
            $desc.Count | Should -Be 2
            foreach ($u in $initialUsers) {
                $found = $desc | Where-Object { $_.sid -eq $u.sid }
                $found | Should -Not -Be $null
                $found.st | Should -Be 'Skip'
            }
        }
        It "Should NOT overwrite an admin-set 'Pending' state when re-discovery returns 'Skip'" {
            # Admin manually flipped one user to Pending and populated un/uid.
            # The next DeviceQuery run (Auto mode, multi-user) would re-discover
            # everyone as Skip. Admin's choice and mapping must be preserved.
            $adminCurated = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-curated-001-001-001-1001"
                    localPath = "C:\Users\AdminPick"
                    un        = "target.user"
                    uid       = "admin-set-uid-12345"
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-curated-002-002-002-1002"
                    localPath = "C:\Users\Other"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $adminCurated | Out-Null

            # Re-discovery: same SIDs, but defaults reset to Skip and un/uid blank
            $rediscovered = @(
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-curated-001-001-001-1001"
                    localPath = "C:\Users\AdminPick"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                },
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Multiple AD users found; awaiting admin selection'
                    sid       = "S-1-5-21-curated-002-002-002-1002"
                    localPath = "C:\Users\Other"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $rediscovered | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = $systemData.description | ConvertFrom-Json
            $picked = $desc | Where-Object { $_.sid -eq "S-1-5-21-curated-001-001-001-1001" }
            $picked.st | Should -Be 'Pending'
            $picked.un | Should -Be 'target.user'
            $picked.uid | Should -Be 'admin-set-uid-12345'
        }
        It "Should NOT overwrite an admin-set 'Skip' state when re-discovery returns 'Pending'" {
            # Admin intentionally skipped a stale account. A subsequent run with
            # DefaultUserState='Pending' (or Auto with only 1 fresh user) must not
            # silently re-queue the skipped user.
            $adminCurated = @(
                [PSCustomObject]@{
                    st        = 'Skip'
                    msg       = 'Stale account; do not migrate'
                    sid       = "S-1-5-21-skipme-001-001-001-1001"
                    localPath = "C:\Users\Stale"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $adminCurated | Out-Null

            $rediscovered = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-skipme-001-001-001-1001"
                    localPath = "C:\Users\Stale"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $rediscovered | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = $systemData.description | ConvertFrom-Json
            $found = $desc | Where-Object { $_.sid -eq "S-1-5-21-skipme-001-001-001-1001" }
            $found.st | Should -Be 'Skip'
            $found.msg | Should -Be 'Stale account; do not migrate'
        }
        It "Should overwrite to 'Complete' when re-discovery confirms a previous migration" {
            # The only auto-overwrite still allowed: discovery has detected the
            # .ADMU profile suffix, so the entry transitions to Complete.
            $initial = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-migration-001-001-001-1001"
                    localPath = "C:\Users\Migrate"
                    un        = "migrated.user"
                    uid       = "mig-uid"
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $initial | Out-Null

            $rediscovered = @(
                [PSCustomObject]@{
                    st        = 'Complete'
                    msg       = 'User previously migrated'
                    sid       = "S-1-5-21-migration-001-001-001-1001"
                    localPath = "C:\Users\Migrate"
                    un        = $null
                    uid       = $null
                    lastLogin = $null
                }
            )
            Set-SystemDesc -ADMUUsers $rediscovered | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = $systemData.description | ConvertFrom-Json
            $found = $desc | Where-Object { $_.sid -eq "S-1-5-21-migration-001-001-001-1001" }
            $found.st | Should -Be 'Complete'
            $found.msg | Should -Be 'User previously migrated'
        }
        It "Should refresh discovery-observed fields (lastLogin/lastWrite/lastLoginValid/profileSize) on subsequent runs" {
            # Initial state: entry with one set of discovery values
            $initial = @(
                [PSCustomObject]@{
                    st             = 'Pending'
                    msg            = 'Planned'
                    sid            = "S-1-5-21-refresh-001-001-001-1001"
                    localPath      = "C:\Users\Refresh"
                    un             = $null
                    uid            = $null
                    lastLogin      = "2025-01-01T10:00:00.0000000Z"
                    lastWrite      = "2025-01-01T10:00:05.0000000Z"
                    lastLoginValid = $true
                    profileSize    = 1.23
                }
            )
            Set-SystemDesc -ADMUUsers $initial | Out-Null

            # Re-discovery: same SID, but discovery values have moved on
            # (user logged in again, profile grew, etc.).
            $rediscovered = @(
                [PSCustomObject]@{
                    st             = 'Pending'
                    msg            = 'Planned'
                    sid            = "S-1-5-21-refresh-001-001-001-1001"
                    localPath      = "C:\Users\Refresh"
                    un             = $null
                    uid            = $null
                    lastLogin      = "2026-05-01T15:30:00.0000000Z"
                    lastWrite      = "2026-05-01T15:30:10.0000000Z"
                    lastLoginValid = $true
                    profileSize    = 4.56
                }
            )
            Set-SystemDesc -ADMUUsers $rediscovered | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = $systemData.description | ConvertFrom-Json
            $found = $desc | Where-Object { $_.sid -eq "S-1-5-21-refresh-001-001-001-1001" }
            $found | Should -Not -BeNullOrEmpty
            $found.lastLogin | Should -Be "2026-05-01T15:30:00.0000000Z"
            $found.lastWrite | Should -Be "2026-05-01T15:30:10.0000000Z"
            $found.profileSize | Should -Be 4.56
        }
        It "Should backfill new schema fields on legacy entries (no lastWrite/lastLoginValid/profileSize) via Add-Member" {
            # Simulate a description written before the new fields existed by
            # bypassing Set-SystemDesc and writing the legacy shape directly.
            $legacyDesc = @(
                [PSCustomObject]@{
                    st        = 'Pending'
                    msg       = 'Planned'
                    sid       = "S-1-5-21-legacy-001-001-001-1001"
                    localPath = "C:\Users\LegacyEntry"
                    un        = $null
                    uid       = $null
                    lastLogin = "2025-01-01T10:00:00.0000000Z"
                }
            )
            Set-System -prop "Description" -Payload $legacyDesc

            # Now run Set-SystemDesc with a record carrying the new fields - the
            # merge loop should add them in place via Add-Member -Force.
            $newUsers = @(
                [PSCustomObject]@{
                    st             = 'Pending'
                    msg            = 'Planned'
                    sid            = "S-1-5-21-legacy-001-001-001-1001"
                    localPath      = "C:\Users\LegacyEntry"
                    un             = $null
                    uid            = $null
                    lastLogin      = "2025-01-01T10:00:00.0000000Z"
                    lastWrite      = "2025-01-01T10:00:05.0000000Z"
                    lastLoginValid = $true
                    profileSize    = 2.5
                }
            )
            Set-SystemDesc -ADMUUsers $newUsers | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = $systemData.description | ConvertFrom-Json
            $found = $desc | Where-Object { $_.sid -eq "S-1-5-21-legacy-001-001-001-1001" }
            $found | Should -Not -BeNullOrEmpty
            # Backfilled fields are now present and populated
            $found.PSObject.Properties.Name | Should -Contain 'lastWrite'
            $found.PSObject.Properties.Name | Should -Contain 'lastLoginValid'
            $found.PSObject.Properties.Name | Should -Contain 'profileSize'
            $found.lastWrite | Should -Be "2025-01-01T10:00:05.0000000Z"
            $found.lastLoginValid | Should -Be $true
            $found.profileSize | Should -Be 2.5
        }
        It "Should refresh discovery fields AND preserve admin-curated state in the same merge" {
            # Initial: admin-curated entry with un/uid populated and Pending state
            $initial = @(
                [PSCustomObject]@{
                    st             = 'Pending'
                    msg            = 'Planned'
                    sid            = "S-1-5-21-mixed-001-001-001-1001"
                    localPath      = "C:\Users\Mixed"
                    un             = "admin.picked.user"
                    uid            = "admin-set-uid-12345"
                    lastLogin      = "2025-01-01T10:00:00.0000000Z"
                    lastWrite      = "2025-01-01T10:00:05.0000000Z"
                    lastLoginValid = $true
                    profileSize    = 1.0
                }
            )
            Set-SystemDesc -ADMUUsers $initial | Out-Null

            # Re-discovery returns Skip default with un/uid blank AND newer
            # discovery values. The merge must:
            #   - PRESERVE admin-curated st/msg/un/uid (Pending + admin's mappings)
            #   - REFRESH lastLogin/lastWrite/lastLoginValid/profileSize
            $rediscovered = @(
                [PSCustomObject]@{
                    st             = 'Skip'
                    msg            = 'Multiple AD users found; awaiting admin selection'
                    sid            = "S-1-5-21-mixed-001-001-001-1001"
                    localPath      = "C:\Users\Mixed"
                    un             = $null
                    uid            = $null
                    lastLogin      = "2026-06-01T12:00:00.0000000Z"
                    lastWrite      = "2026-06-01T12:00:00.0000000Z"
                    lastLoginValid = $true
                    profileSize    = 5.5
                }
            )
            Set-SystemDesc -ADMUUsers $rediscovered | Out-Null

            $systemData = Get-System -systemContextBinding $true
            $desc = $systemData.description | ConvertFrom-Json
            $found = $desc | Where-Object { $_.sid -eq "S-1-5-21-mixed-001-001-001-1001" }
            # Admin-curated state preserved
            $found.st | Should -Be 'Pending'
            $found.msg | Should -Be 'Planned'
            $found.un | Should -Be 'admin.picked.user'
            $found.uid | Should -Be 'admin-set-uid-12345'
            # Discovery fields refreshed
            $found.lastLogin | Should -Be "2026-06-01T12:00:00.0000000Z"
            $found.lastWrite | Should -Be "2026-06-01T12:00:00.0000000Z"
            $found.profileSize | Should -Be 5.5
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
    Context "Set-System Retry and Error Handling" {
        It "Should attempt retries and exit with code 1 upon exhaustion" {
            # 1. Mock Get-Content to bypass systemKey/URL discovery
            Mock Get-Content -MockWith { return 'systemKey":"mockKey";"agentServerHost":"agent.jumpcloud.com"' }

            # 2. Mock Invoke-RestMethod to ALWAYS fail
            # This triggers the 'catch' block in Set-System
            Mock Invoke-RestMethod -MockWith { throw "Connection Timeout" }

            # 3. Use a small retry count/delay to keep the test fast
            $params = @{
                prop              = "Description"
                payload           = "Test"
                maxRetries        = 2
                retryDelaySeconds = 0
            }

            # 4. We use a try/catch in the test to catch the 'exit' call
            # In Pester, 'exit' inside a scriptblock usually throws a specific
            # termination error that we can inspect.
            { Set-System @params } | Should -Throw

            # 5. Verify the mocks were called exactly 'maxRetries' times
            Assert-MockCalled Invoke-RestMethod -Times 2
        }

        It "Should wait for exponential backoff between retries" {
            Mock Get-Content -MockWith { return 'systemKey":"mockKey";"agentServerHost":"agent.jumpcloud.com"' }
            Mock Invoke-RestMethod -MockWith { throw "Temporary Failure" }

            # Mock Start-Sleep so the test doesn't actually wait
            Mock Start-Sleep -MockWith { return }

            $maxRetries = 3
            try {
                Set-System -prop "Description" -payload "Test" -maxRetries $maxRetries -retryDelaySeconds 1
            } catch {
                # We catch the 'exit 1' / 'Write-Error' here so the test
                # can proceed to the Assert-MockCalled lines below.
                Write-Host "Caught expected exhaustion exit: $($_.Exception.Message)"
            }
            # Verify Start-Sleep was called for retries (maxRetries - 1)
            Assert-MockCalled Start-Sleep -Times 2
        }
    }
}