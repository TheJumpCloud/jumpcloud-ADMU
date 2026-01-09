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
            $resultObj = $result | ConvertFrom-Json
            $resultObj | Should -BeOfType System.Object
            $resultObj.Count | Should -Be 1

            $firstEntry = $resultObj[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1001"
            $firstEntry.un | Should -Be "testuser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:\Users\testuser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
        It "Sets the device description to a json list containing on object with the provided parameters and the SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-1002" -MigrationUsername "anotheruser" -StatusMessage "Migration started" -Percent "0%" -LocalPath "C:\Users\anotheruser" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $resultObj = $result | ConvertFrom-Json
            $resultObj | Should -BeOfType System.Object
            $resultObj.Count | Should -Be 1

            $firstEntry = $resultObj[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1002"
            $firstEntry.un | Should -Be "anotheruser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:\Users\anotheruser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
    }
    Context "When the system description has existing migration data" {
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
            $resultObj = $result | ConvertFrom-Json
            $resultObj | Should -BeOfType System.Object
            $resultObj.Count | Should -Be 1

            $firstEntry = $resultObj[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-2001"
            $firstEntry.un | Should -Be "existinguser"
            $firstEntry.uid | Should -Be 42
            $firstEntry.localPath | Should -Be "C:\Users\existinguser"
            $firstEntry.msg | Should -Be "Re-migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
        It "Updates the existing user object when the SID matches and preserves the UID with SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-2001" -MigrationUsername "existinguser" -StatusMessage "Re-migration started" -Percent "50%" -LocalPath "C:\Users\existinguser" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $resultObj = $result | ConvertFrom-Json
            $resultObj | Should -BeOfType System.Object
            $resultObj.Count | Should -Be 1

            $firstEntry = $resultObj[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-2001"
            $firstEntry.un | Should -Be "existinguser"
            $firstEntry.uid | Should -Be 42
            $firstEntry.localPath | Should -Be "C:\Users\existinguser"
            $firstEntry.msg | Should -Be "Re-migration started"
            $firstEntry.st | Should -Be "inProgress"
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
            $resultObj = $result | ConvertFrom-Json
            $resultObj | Should -BeOfType System.Object
            $resultObj.Count | Should -Be 1

            $firstEntry = $resultObj[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1001"
            $firstEntry.un | Should -Be "testuser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:\Users\testuser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
        It "Replaces the existing description with specified data using SystemContextAPI auth method" {
            $script:validatedSystemContextAPI = $true
            $script:validatedSystemID = $systemKey

            $result = Build-MigrationDescription -UserSID "S-1-5-21-1234567890-123456789-123456789-1002" -MigrationUsername "anotheruser" -StatusMessage "Migration started" -Percent "0%" -LocalPath "C:\Users\anotheruser" -AuthMethod "systemcontextapi"

            $result | Should -Not -BeNullOrEmpty
            $resultObj = $result | ConvertFrom-Json
            $resultObj | Should -BeOfType System.Object
            $resultObj.Count | Should -Be 1
            $firstEntry = $resultObj[0]
            $firstEntry.sid | Should -Be "S-1-5-21-1234567890-123456789-123456789-1002"
            $firstEntry.un | Should -Be "anotheruser"
            $firstEntry.uid | Should -Be $null
            $firstEntry.localPath | Should -Be "C:\Users\anotheruser"
            $firstEntry.msg | Should -Be "Migration started"
            $firstEntry.st | Should -Be "inProgress"
        }
    }
}
