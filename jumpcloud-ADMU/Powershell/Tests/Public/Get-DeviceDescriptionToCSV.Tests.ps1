Describe "Get-DeviceDescriptionToCSV Tests" -Tag "InstallJC" {
    BeforeAll {
        $scriptPath = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\DeviceInit\Get-DeviceDescriptionToCSV.ps1'
        if (-not (Test-Path $scriptPath)) {
            throw "TEST SETUP FAILED: Script not found at: $scriptPath"
        }
        $scriptContent = Get-Content -Path $scriptPath -Raw
        $pattern = '\#region Functions[\s\S]*\#endregion Functions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)
        if (-not $functionMatches.Success) {
            throw "TEST SETUP FAILED: Could not extract Functions region from script."
        }
        $tempFunctionFile = Join-Path $PSScriptRoot 'GetDeviceDescriptionToCSVFunctions.ps1'
        $functionMatches.Value | Set-Content -Path $tempFunctionFile -Force
        . $tempFunctionFile
    }

    Context "API key validation" {
        It "Should throw when JCApiKey is not set" {
            $env:JCApiKey = $null
            { Get-DeviceDescriptionToCSV -OutputPath (Join-Path $TestDrive "out.csv") } | Should -Throw -ExpectedMessage "*JumpCloud API Key must be configured*"
        }

        It "Should throw when JCApiKey is placeholder 'YOUR_API_KEY_HERE'" {
            $env:JCApiKey = "YOUR_API_KEY_HERE"
            { Get-DeviceDescriptionToCSV -OutputPath (Join-Path $TestDrive "out.csv") } | Should -Throw -ExpectedMessage "*JumpCloud API Key must be configured*"
        }
    }

    Context "No data" {
        It "Should return null when no user objects exist" {
            $env:JCApiKey = "test-api-key"
            Mock Get-JcSdkSystem { return @() }
            $result = Get-DeviceDescriptionToCSV -OutputPath (Join-Path $TestDrive "empty.csv")
            $result | Should -Be $null
        }

        It "Should return null when all systems have empty description" {
            $env:JCApiKey = "test-api-key"
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{ id = "dev1"; hostname = "host1"; displayName = "Host 1"; description = "" }
                )
            }
            $result = Get-DeviceDescriptionToCSV -OutputPath (Join-Path $TestDrive "empty.csv")
            $result | Should -Be $null
        }
    }

    Context "Happy path" {
        It "Should return report data and write CSV when systems have valid JSON descriptions" {
            $env:JCApiKey = "test-api-key"
            $descJson = '[{"sid":"S-1-5-21-123","un":"user1","st":"Pending","msg":"","localPath":"C:\\Users\\user1","uid":"","LastLogin":""}]'
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{
                        id          = "device-id-1"
                        hostname    = "WORKSTATION1"
                        displayName = "Workstation 1"
                        description = $descJson
                    }
                )
            }
            $outPath = Join-Path $TestDrive "report.csv"
            $result = @(Get-DeviceDescriptionToCSV -OutputPath $outPath)
            $result | Should -Not -Be $null
            $result.Count | Should -Be 1
            $result[0].DeviceID | Should -Be "device-id-1"
            $result[0].Hostname | Should -Be "WORKSTATION1"
            $result[0].SID | Should -Be "S-1-5-21-123"
            $result[0].Username | Should -Be "user1"
            Test-Path $outPath | Should -Be $true
            (Get-Content $outPath).Count | Should -BeGreaterThan 1
        }
    }

    Context "Single vs array" {
        It "Should treat single user object in description as single-element array" {
            $env:JCApiKey = "test-api-key"
            $descJson = '[{"sid":"S-1-5-21-456","un":"u1"}]'
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{
                        id          = "dev-single"
                        hostname    = "SINGLE"
                        displayName = "Single"
                        description = $descJson
                    }
                )
            }
            $outPath = Join-Path $TestDrive "single.csv"
            $result = @(Get-DeviceDescriptionToCSV -OutputPath $outPath)
            $result | Should -Not -Be $null
            $result.Count | Should -Be 1
            $result[0].SID | Should -Be "S-1-5-21-456"
            $result[0].Username | Should -Be "u1"
        }
    }

    Context "Skips and warnings" {
        It "Should skip systems with empty description" {
            $env:JCApiKey = "test-api-key"
            $descJson = '[{"sid":"S-1-5-21-789","un":"u2"}]'
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{ id = "dev-empty"; hostname = "EMPTY"; displayName = "Empty"; description = "" },
                    [PSCustomObject]@{
                        id          = "dev-with-desc"
                        hostname    = "WITH_DESC"
                        displayName = "With Desc"
                        description = $descJson
                    }
                )
            }
            $outPath = Join-Path $TestDrive "mixed.csv"
            $result = @(Get-DeviceDescriptionToCSV -OutputPath $outPath)
            $result | Should -Not -Be $null
            $result.Count | Should -Be 1
            $result[0].Hostname | Should -Be "WITH_DESC"
        }

        It "Should skip systems with invalid JSON description" {
            $env:JCApiKey = "test-api-key"
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{
                        id          = "dev-bad-json"
                        hostname    = "BAD_JSON"
                        displayName = "Bad"
                        description = "not valid json {{{"
                    }
                )
            }
            $outPath = Join-Path $TestDrive "bad.csv"
            $result = Get-DeviceDescriptionToCSV -OutputPath $outPath
            $result | Should -Be $null
        }
    }

    Context "CSV shape" {
        It "Should export CSV with expected columns" {
            $env:JCApiKey = "test-api-key"
            $descJson = '[{"sid":"S-1-5-21-111","un":"u1","st":"Pending","msg":"","localPath":"","uid":"uid1","LastLogin":""}]'
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{
                        id          = "dev1"
                        hostname    = "H1"
                        displayName = "D1"
                        description = $descJson
                    }
                )
            }
            $outPath = Join-Path $TestDrive "columns.csv"
            $null = Get-DeviceDescriptionToCSV -OutputPath $outPath
            $rows = @(Import-Csv -Path $outPath)
            $rows.Count | Should -Be 1
            $expectedColumns = @('DeviceID', 'Hostname', 'DisplayName', 'SID', 'Username', 'Status', 'Message', 'LocalPath', 'UserID', 'LastLogin')
            foreach ($col in $expectedColumns) {
                $rows[0].PSObject.Properties.Name | Should -Contain $col
            }
        }
    }

    Context "OutputPath" {
        It "Should write to the path specified by OutputPath" {
            $env:JCApiKey = "test-api-key"
            $descJson = '[{"sid":"S-1-5-21-222","un":"u2"}]'
            Mock Get-JcSdkSystem {
                return @(
                    [PSCustomObject]@{
                        id          = "dev2"
                        hostname    = "H2"
                        displayName = "D2"
                        description = $descJson
                    }
                )
            }
            $customPath = Join-Path $TestDrive "custom_report.csv"
            $null = Get-DeviceDescriptionToCSV -OutputPath $customPath
            Test-Path $customPath | Should -Be $true
            $content = Get-Content $customPath -Raw
            $content | Should -Match "DeviceID"
            $content | Should -Match "S-1-5-21-222"
        }
    }
}
