Describe "Set-DeviceDescriptionFromCSV Tests" -Tag "InstallJC" {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\DeviceInit\Set-DeviceDescriptionFromCSV.ps1'
        if (-not (Test-Path $scriptPath)) {
            throw "TEST SETUP FAILED: Script not found at: $scriptPath"
        }
        $scriptContent = Get-Content -Path $scriptPath -Raw
        $pattern = '\#region Functions[\s\S]*\#endregion Functions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)
        if (-not $functionMatches.Success) {
            throw "TEST SETUP FAILED: Could not extract Functions region from script."
        }
        $tempFunctionFile = Join-Path $PSScriptRoot 'SetDeviceDescriptionFromCSVFunctions.ps1'
        $functionMatches.Value | Set-Content -Path $tempFunctionFile -Force
        . $tempFunctionFile
    }

    Context "Sync-DeviceDescriptions - CSV missing" {
        It "Should throw when CSV file is not found" {
            { Sync-DeviceDescriptions -CsvPath "C:\Nonexistent\file.csv" -PreviewChanges $false -Confirm $false } | Should -Throw -ExpectedMessage "*not found*"
        }
    }

    Context "Sync-DeviceDescriptions - Preview and apply" {
        It "Should call Update-JCSystemDescription with correct JSON when changes are confirmed with -Confirm false" {
            $csvPath = Join-Path $TestDrive "sync.csv"
            $currentDesc = '[{"sid":"S-1-5-21-AAA","un":"olduser","st":"Pending","msg":"","localPath":"","uid":""}]'
            @(
                [PSCustomObject]@{
                    DeviceID    = "dev-123"
                    Hostname    = "HOST1"
                    DisplayName = "Host 1"
                    SID         = "S-1-5-21-AAA"
                    Username    = "jcuser1"
                    Status      = ""
                    Message     = ""
                    LocalPath   = ""
                    UserID      = "jcuid1"
                    LastLogin   = ""
                }
            ) | Export-Csv -Path $csvPath -NoTypeInformation -Force

            Mock Get-JCUser {
                return @(
                    [PSCustomObject]@{ _id = "jcuid1"; username = "jcuser1" }
                )
            }
            Mock Get-JcSdkSystem -ParameterFilter { $Id -eq "dev-123" } {
                return [PSCustomObject]@{ id = "dev-123"; description = $currentDesc }
            }
            Mock Set-JCSystem { return $true }

            $result = Sync-DeviceDescriptions -CsvPath $csvPath -PreviewChanges $true -Confirm $false

            $result | Should -Be $true
            Assert-MockCalled Set-JCSystem -Times 1 -Scope It
            Assert-MockCalled Set-JCSystem -ParameterFilter { $SystemID -eq "dev-123" } -Scope It
        }

        It "Should not update when user responds non-yes to prompt" {
            $csvPath = Join-Path $TestDrive "sync_no.csv"
            $currentDesc = '[{"sid":"S-1-5-21-BBB","un":"u","st":"Pending","msg":"","localPath":"","uid":""}]'
            @(
                [PSCustomObject]@{
                    DeviceID    = "dev-456"
                    Hostname    = "HOST2"
                    DisplayName = "Host 2"
                    SID         = "S-1-5-21-BBB"
                    Username    = "jcuser2"
                    Status      = ""
                    Message     = ""
                    LocalPath   = ""
                    UserID      = "jcuid2"
                    LastLogin   = ""
                }
            ) | Export-Csv -Path $csvPath -NoTypeInformation -Force

            Mock Get-JCUser { return @([PSCustomObject]@{ _id = "jcuid2"; username = "jcuser2" }) }
            Mock Get-JcSdkSystem -ParameterFilter { $Id -eq "dev-456" } {
                return [PSCustomObject]@{ id = "dev-456"; description = $currentDesc }
            }
            Mock Set-JCSystem { return $true }
            Mock Read-Host { return "no" }

            $result = Sync-DeviceDescriptions -CsvPath $csvPath -PreviewChanges $true -Confirm $true

            $result | Should -Be $false
            Assert-MockCalled Set-JCSystem -Times 0 -Scope It
        }
    }

    Context "Sync-DeviceDescriptions - Validation errors" {
        It "Should collect validation errors and skip invalid users" {
            $csvPath = Join-Path $TestDrive "invalid_user.csv"
            $currentDesc = '[{"sid":"S-1-5-21-CCC","un":"","st":"Pending","msg":"","localPath":"","uid":""}]'
            @(
                [PSCustomObject]@{
                    DeviceID    = "dev-789"
                    Hostname    = "HOST3"
                    DisplayName = "Host 3"
                    SID         = "S-1-5-21-CCC"
                    Username    = "nonexistent_user"
                    Status      = ""
                    Message     = ""
                    LocalPath   = ""
                    UserID      = "nonexistent_uid"
                    LastLogin   = ""
                }
            ) | Export-Csv -Path $csvPath -NoTypeInformation -Force

            Mock Get-JCUser { return @() }
            Mock Get-JcSdkSystem -ParameterFilter { $Id -eq "dev-789" } {
                return [PSCustomObject]@{ id = "dev-789"; description = $currentDesc }
            }
            Mock Set-JCSystem { return $true }

            $result = Sync-DeviceDescriptions -CsvPath $csvPath -PreviewChanges $false -Confirm $false

            $result | Should -Be $true
            Assert-MockCalled Set-JCSystem -Times 0 -Scope It
        }
    }

    Context "Sync-DeviceDescriptions - Skip devices" {
        It "Should skip device when description is empty" {
            $csvPath = Join-Path $TestDrive "empty_desc.csv"
            @(
                [PSCustomObject]@{
                    DeviceID    = "dev-empty"
                    Hostname    = "EMPTY"
                    DisplayName = "Empty"
                    SID         = "S-1-5-21-DDD"
                    Username    = "u"
                    Status      = ""
                    Message     = ""
                    LocalPath   = ""
                    UserID      = "uid"
                    LastLogin   = ""
                }
            ) | Export-Csv -Path $csvPath -NoTypeInformation -Force

            Mock Get-JCUser { return @() }
            Mock Get-JcSdkSystem -ParameterFilter { $Id -eq "dev-empty" } {
                return [PSCustomObject]@{ id = "dev-empty"; description = "" }
            }
            Mock Set-JCSystem { return $true }

            $result = Sync-DeviceDescriptions -CsvPath $csvPath -PreviewChanges $false -Confirm $false

            $result | Should -Be $true
            Assert-MockCalled Set-JCSystem -Times 0 -Scope It
        }

        It "Should skip device when description is not valid JSON" {
            $csvPath = Join-Path $TestDrive "bad_json.csv"
            @(
                [PSCustomObject]@{
                    DeviceID    = "dev-bad"
                    Hostname    = "BAD"
                    DisplayName = "Bad"
                    SID         = "S-1-5-21-EEE"
                    Username    = "u"
                    Status      = ""
                    Message     = ""
                    LocalPath   = ""
                    UserID      = "uid"
                    LastLogin   = ""
                }
            ) | Export-Csv -Path $csvPath -NoTypeInformation -Force

            Mock Get-JCUser { return @() }
            Mock Get-JcSdkSystem -ParameterFilter { $Id -eq "dev-bad" } {
                return [PSCustomObject]@{ id = "dev-bad"; description = "not json {{{" }
            }
            Mock Set-JCSystem { return $true }

            $result = Sync-DeviceDescriptions -CsvPath $csvPath -PreviewChanges $false -Confirm $false

            $result | Should -Be $true
            Assert-MockCalled Set-JCSystem -Times 0 -Scope It
        }
    }

    Context "Test-UserValidity" {
        BeforeEach {
            $userLookup = @{
                ById       = @{
                    "uid1" = [PSCustomObject]@{ _id = "uid1"; username = "user1" }
                }
                ByUsername = @{
                    "user1" = [PSCustomObject]@{ _id = "uid1"; username = "user1" }
                }
            }
        }

        It "Should be valid when username and userID match lookup" {
            $result = Test-UserValidity -Username "user1" -UserID "uid1" -UserLookup $userLookup
            $result.IsValid | Should -Be $true
            $result.Errors.Count | Should -Be 0
        }

        It "Should be invalid when username not in JumpCloud" {
            $result = Test-UserValidity -Username "unknownuser" -UserID $null -UserLookup $userLookup
            $result.IsValid | Should -Be $false
            $result.Errors | Should -Match "not found"
        }

        It "Should be invalid when userID not in JumpCloud" {
            $result = Test-UserValidity -Username $null -UserID "unknownid" -UserLookup $userLookup
            $result.IsValid | Should -Be $false
            $result.Errors | Should -Match "not found"
        }

        It "Should be invalid when username and userID do not match same user" {
            $lookup = @{
                ById       = @{
                    "uid1" = [PSCustomObject]@{ _id = "uid1"; username = "user1" }
                    "uid2" = [PSCustomObject]@{ _id = "uid2"; username = "user2" }
                }
                ByUsername = @{
                    "user1" = [PSCustomObject]@{ _id = "uid1"; username = "user1" }
                    "user2" = [PSCustomObject]@{ _id = "uid2"; username = "user2" }
                }
            }
            $result = Test-UserValidity -Username "user1" -UserID "uid2" -UserLookup $lookup
            $result.IsValid | Should -Be $false
            $result.Errors | Should -Match "not "
        }
    }

    Context "Compare-UserObjects" {
        It "Should report differences for un, st, msg, localPath, uid between current and CSV object" {
            $currentObj = [PSCustomObject]@{ sid = "S-1"; un = "old"; st = "Pending"; msg = "m1"; localPath = "C:\Old"; uid = "u1" }
            $csvObj = [PSCustomObject]@{ Username = "new"; Status = "Complete"; Message = "m2"; LocalPath = "C:\New"; UserID = "u2" }
            $diffs = Compare-UserObjects -CurrentObj $currentObj -CsvObj $csvObj
            $diffs.Count | Should -BeGreaterThan 0
            $diffs.Property | Should -Contain "Username"
            ($diffs | Where-Object { $_.Property -eq "Username" }).Current | Should -Be "old"
            ($diffs | Where-Object { $_.Property -eq "Username" }).Updated | Should -Be "new"
        }

        It "Should report no differences when values match" {
            $currentObj = [PSCustomObject]@{ sid = "S-1"; un = "same"; st = "Pending"; msg = ""; localPath = ""; uid = "uid1" }
            $csvObj = [PSCustomObject]@{ Username = "same"; Status = "Pending"; Message = ""; LocalPath = ""; UserID = "uid1" }
            $diffs = Compare-UserObjects -CurrentObj $currentObj -CsvObj $csvObj
            $diffs.Count | Should -Be 0
        }

        It "Should not report difference when both values are empty" {
            $currentObj = [PSCustomObject]@{ sid = "S-1"; un = ""; st = ""; msg = ""; localPath = ""; uid = "" }
            $csvObj = [PSCustomObject]@{ Username = ""; Status = ""; Message = ""; LocalPath = ""; UserID = "" }
            $diffs = Compare-UserObjects -CurrentObj $currentObj -CsvObj $csvObj
            $diffs.Count | Should -Be 0
        }
    }

    Context "Get-JCSystemDescription and Update-JCSystemDescription" {
        It "Get-JCSystemDescription returns description from Get-JcSdkSystem" {
            Mock Get-JcSdkSystem -ParameterFilter { $Id -eq "sys-1" } {
                return [PSCustomObject]@{ id = "sys-1"; description = "expected description" }
            }
            $result = Get-JCSystemDescription -SystemID "sys-1"
            $result | Should -Be "expected description"
        }

        It "Update-JCSystemDescription calls Set-JCSystem" {
            Mock Set-JCSystem { return $true }
            Update-JCSystemDescription -SystemID "sys-2" -NewDescription '{"test":true}'
            Assert-MockCalled Set-JCSystem -Times 1 -ParameterFilter {
                $SystemID -eq "sys-2" -and $description -eq '{"test":true}'
            } -Scope It
        }
    }

    Context "Get-JCUserLookup" {
        It "Returns lookup with ById and ByUsername and correct counts" {
            Mock Get-JCUser {
                return @(
                    [PSCustomObject]@{ _id = "id1"; username = "u1" },
                    [PSCustomObject]@{ _id = "id2"; username = "u2" }
                )
            }
            $lookup = Get-JCUserLookup
            $lookup.ById.Keys.Count | Should -Be 2
            $lookup.ByUsername.Keys.Count | Should -Be 2
            $lookup.ById["id1"].username | Should -Be "u1"
            $lookup.ByUsername["u2"]._id | Should -Be "id2"
        }
    }

    Context "Update-CSVWithValidatedUser" {
        It "Populates Username from lookup when CSV user has UserID only" {
            $lookup = @{
                ById       = @{ "uid1" = [PSCustomObject]@{ _id = "uid1"; username = "filleduser" } }
                ByUsername = @{ "filleduser" = [PSCustomObject]@{ _id = "uid1"; username = "filleduser" } }
            }
            $csvUser = [PSCustomObject]@{ Username = ""; UserID = "uid1" }
            $validationResult = [PSCustomObject]@{ IsValid = $true; Errors = @() }
            Update-CSVWithValidatedUser -CsvUser $csvUser -ValidationResult $validationResult -UserLookup $lookup
            $csvUser.Username | Should -Be "filleduser"
        }

        It "Populates UserID from lookup when CSV user has Username only" {
            $lookup = @{
                ById       = @{ "filledid" = [PSCustomObject]@{ _id = "filledid"; username = "u1" } }
                ByUsername = @{ "u1" = [PSCustomObject]@{ _id = "filledid"; username = "u1" } }
            }
            $csvUser = [PSCustomObject]@{ Username = "u1"; UserID = "" }
            $validationResult = [PSCustomObject]@{ IsValid = $true; Errors = @() }
            Update-CSVWithValidatedUser -CsvUser $csvUser -ValidationResult $validationResult -UserLookup $lookup
            $csvUser.UserID | Should -Be "filledid"
        }
    }
}
