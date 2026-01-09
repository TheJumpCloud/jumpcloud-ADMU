Describe "Build-MigrationDescription Acceptance Tests" -Tag "InstallJC" {
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

        # get the system key
        $config = Get-Content "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value

        Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -force
    }
    Context "When the system description is null" {
        BeforeEach {
            # Set the current systemID description to null
            Set-JCSystem -SystemID $systemKey -description $null
        }
        It "Sets the device description to a json list containing on object with the provided parameters and the API key auth method" {
            $script:JumpCloudAPIKey = $env:PESTER_APIKEY
            $script:JumpCloudOrgID = $env:PESTER_ORGID
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-1001" -MigrationUsername "testuser" -StatusMessage "Migration started" -Percent "0%" -LocalPath "C:\Users\testuser" -AuthMethod "apikey"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 1

            $firstEntry = $result[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1001"
            $firstEntry.un | Should -Be "testuser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:/Users/testuser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
        It "Sets the device description to a json list containing on object with the provided parameters and the SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-1002" -MigrationUsername "anotheruser" -StatusMessage "Migration started" -Percent "0%" -LocalPath "C:\Users\anotheruser" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 1

            $firstEntry = $result[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1002"
            $firstEntry.un | Should -Be "anotheruser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:/Users/anotheruser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
    }
    Context "When the system description has existing migration data for the current user" {
        BeforeEach {
            # Set the current systemID description to a json list with one user object
            $initialDescription = @(
                @{
                    sid       = "S-1-5-21-1234567890-123456789-123456789-2001"
                    un        = "existinguser"
                    localPath = "C:/Users/existinguser"
                    msg       = "Previous migration completed"
                    st        = "completed"
                    uid       = 42
                }
            ) | ConvertTo-Json

            Set-JCSystem -SystemID $systemKey -description $initialDescription
        }
        It "Updates the existing user object when the SID matches and preserves the UID with API key auth method" {
            $script:JumpCloudAPIKey = $env:PESTER_APIKEY
            $script:JumpCloudOrgID = $env:PESTER_ORGID
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-2001" -MigrationUsername "existinguser" -StatusMessage "Re-migration started" -Percent "50%" -LocalPath "C:\Users\existinguser" -AuthMethod "apikey"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 1

            $firstEntry = $result[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-2001"
            $firstEntry.un | Should -Be "existinguser"
            $firstEntry.uid | Should -Be 42
            $firstEntry.localPath | Should -Be "C:/Users/existinguser"
            $firstEntry.msg | Should -Be "Re-migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
        It "Updates the existing user object when the SID matches and preserves the UID with SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-2001" -MigrationUsername "existinguser" -StatusMessage "Re-migration started" -Percent "50%" -LocalPath "C:\Users\existinguser" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 1

            $firstEntry = $result[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-2001"
            $firstEntry.un | Should -Be "existinguser"
            $firstEntry.uid | Should -Be 42
            $firstEntry.localPath | Should -Be "C:/Users/existinguser"
            $firstEntry.msg | Should -Be "Re-migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
    }
    Context "When the system description has existing data for multiple users" {
        BeforeEach {
            # Set the current systemID description to a json list with multiple user objects
            $initialDescription = @(
                @{
                    sid       = "S-1-5-21-1234567890-123456789-123456789-3001"
                    un        = "userone"
                    localPath = "C:/Users/userone"
                    msg       = "Migration completed"
                    st        = "completed"
                    uid       = 101
                }
                @{
                    sid       = "S-1-5-21-1234567890-123456789-123456789-3002"
                    un        = "usertwo"
                    localPath = "C:/Users/usertwo"
                    msg       = "Migration in progress"
                    st        = "inProgress"
                    uid       = 102
                }
            ) | ConvertTo-Json

            $setSystem = Set-JCSystem -SystemID $systemKey -description $initialDescription
            $setSystemDescription = $setSystem | Select-Object -ExpandProperty Description | ConvertFrom-Json
        }
        It "Updates only the matching user object and preserves UIDs with API key auth method" {
            $script:JumpCloudAPIKey = $env:PESTER_APIKEY
            $script:JumpCloudOrgID = $env:PESTER_ORGID
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-3002" -MigrationUsername "usertwo" -StatusMessage "Migration completed" -Percent "100%" -LocalPath "C:\Users\usertwo" -AuthMethod "apikey"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 2

            $firstEntry = $result | Where-Object { $_.sid -eq "S-1-5-21-1234567890-123456789-123456789-3001" }
            $firstEntry.un | Should -Be "userone"
            $firstEntry.uid | Should -Be 101
            $firstEntry.localPath | Should -Be "C:/Users/userone"

            $matchingEntry = $result | Where-Object { $_.sid -eq "S-1-5-21-1234567890-123456789-123456789-3002" }
            $matchingEntry.un | Should -Be "usertwo"
            $matchingEntry.uid | Should -Be 102
            $matchingEntry.localPath | Should -Be "C:/Users/usertwo"
            $matchingEntry.msg | Should -Be "Migration completed"
            $matchingEntry.st | Should -Be "completed"
        }
        It "Updates only the matching user object and preserves UIDs with SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-3002" -MigrationUsername "usertwo" -StatusMessage "Migration completed" -Percent "100%" -LocalPath "C:\Users\usertwo" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 2

            $firstEntry = $result | Where-Object { $_.sid -eq "S-1-5-21-1234567890-123456789-123456789-3001" }
            $firstEntry.un | Should -Be "userone"
            $firstEntry.uid | Should -Be 101
            $firstEntry.localPath | Should -Be "C:/Users/userone"

            $matchingEntry = $result | Where-Object { $_.sid -eq "S-1-5-21-1234567890-123456789-123456789-3002" }
            $matchingEntry.un | Should -Be "usertwo"
            $matchingEntry.uid | Should -Be 102
            $matchingEntry.localPath | Should -Be "C:/Users/usertwo"
            $matchingEntry.msg | Should -Be "Migration completed"
            $matchingEntry.st | Should -Be "completed"
        }
    }
    Context "When the system description has existing data but no user SIDs" {
        BeforeEach {
            # Set the current systemID description to a json list with one user object without SID
            Set-JCSystem -SystemID $systemKey -description "Existing non-JSON description data"
        }
        It "Replaces the existing description with specified data using API key auth method" {
            $script:JumpCloudAPIKey = $env:PESTER_APIKEY
            $script:JumpCloudOrgID = $env:PESTER_ORGID
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-1001" -MigrationUsername "testuser" -StatusMessage "Migration started" -Percent "0%" -LocalPath "C:\Users\testuser" -AuthMethod "apikey"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 1

            $firstEntry = $result[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1001"
            $firstEntry.un | Should -Be "testuser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:/Users/testuser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
        It "Replaces the existing description with specified data using SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-1002" -MigrationUsername "anotheruser" -StatusMessage "Migration started" -Percent "0%" -LocalPath "C:\Users\anotheruser" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $result | Should -BeOfType System.Object
            $result.Count | Should -Be 1
            $firstEntry = $result[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1002"
            $firstEntry.un | Should -Be "anotheruser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:/Users/anotheruser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
    }
}
