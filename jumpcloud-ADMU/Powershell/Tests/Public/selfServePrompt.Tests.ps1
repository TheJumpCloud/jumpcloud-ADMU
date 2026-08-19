Describe "ADMU Self-Service Prompt Script Tests" -Tag "Self Serve Prompt" {
    BeforeAll {
        # Locate the self-service prompt command script.
        $global:selfServeScript = Join-Path $PSScriptRoot '..\..\..\..\jumpcloud-ADMU-Advanced-Deployment\InvokeFromJCAgent\4_ADMU_SelfServePrompt.ps1'
        if (-not (Test-Path $global:selfServeScript)) {
            throw "TEST SETUP FAILED: Script not found at: $($global:selfServeScript)"
        }

        # Extract only the function definitions (avoid running the main region on dot-source).
        $scriptContent = Get-Content -Path $global:selfServeScript -Raw
        $pattern = '\#region functions[\s\S]*\#endregion functions'
        $functionMatches = [regex]::Matches($scriptContent, $pattern)
        $tempFunctionFile = Join-Path $PSScriptRoot 'selfServeFunctions.ps1'
        $functionMatches.Value | Set-Content -Path $tempFunctionFile -Force
        . $tempFunctionFile
    }

    AfterAll {
        Remove-Item -Path (Join-Path $PSScriptRoot 'selfServeFunctions.ps1') -Force -ErrorAction SilentlyContinue
    }

    Context 'Get-DeviceMigrationUser (CSV)' {
        BeforeEach {
            Mock Test-Path { $true }
            Mock Get-CimInstance { [PSCustomObject]@{ SerialNumber = 'SN123' } } -ParameterFilter { $ClassName -eq 'Win32_BIOS' }
        }
        It 'returns the row matching this computer + serial (and ignores other devices)' {
            Mock Import-Csv {
                @(
                    [PSCustomObject]@{ LocalComputerName = $env:COMPUTERNAME; SerialNumber = 'SN123'; JumpCloudUserName = 'jdoe'; SID = 'S-1-5-21-1-2-3-1001'; LocalPath = 'C:\Users\jdoe'; JumpCloudUserID = 'uid1' },
                    [PSCustomObject]@{ LocalComputerName = 'OTHERPC'; SerialNumber = 'SNX'; JumpCloudUserName = 'other'; SID = 'S-1-5-21-9-9-9-9'; LocalPath = 'C:\Users\other'; JumpCloudUserID = 'uid2' }
                )
            }
            $t = @(Get-DeviceMigrationUser -Source 'CSV' -CsvName 'jcdiscovery.csv')
            $t.Count | Should -Be 1
            $t[0].JumpCloudUserName | Should -Be 'jdoe'
            $t[0].SID | Should -Be 'S-1-5-21-1-2-3-1001'
        }
        It 'returns empty when no row matches this device' {
            Mock Import-Csv { @([PSCustomObject]@{ LocalComputerName = 'OTHERPC'; SerialNumber = 'SNX'; JumpCloudUserName = 'other'; SID = 'S-1'; LocalPath = 'p'; JumpCloudUserID = 'u' }) }
            @(Get-DeviceMigrationUser -Source 'CSV').Count | Should -Be 0
        }
        It 'throws when a required header is missing' {
            Mock Import-Csv { @([PSCustomObject]@{ LocalComputerName = $env:COMPUTERNAME; SerialNumber = 'SN123'; JumpCloudUserName = 'jdoe' }) }
            { Get-DeviceMigrationUser -Source 'CSV' } | Should -Throw
        }
        It 'throws when the CSV file is missing' {
            Mock Test-Path { $false }
            { Get-DeviceMigrationUser -Source 'CSV' } | Should -Throw
        }
    }

    Context 'Test-SidLoggedIn' {
        It 'is true when the user hive is loaded' {
            Mock Test-Path { $true } -ParameterFilter { $Path -like 'Registry::HKEY_USERS\*' }
            Test-SidLoggedIn -Sid 'S-1-5-21-1-2-3-1001' | Should -Be $true
        }
        It 'is false when the hive is not loaded' {
            Mock Test-Path { $false } -ParameterFilter { $Path -like 'Registry::HKEY_USERS\*' }
            Test-SidLoggedIn -Sid 'S-1-5-21-1-2-3-1001' | Should -Be $false
        }
    }

    Context 'Convert-SidToAccount' {
        It 'resolves the well-known SYSTEM SID' {
            Convert-SidToAccount -Sid 'S-1-5-18' | Should -Match 'SYSTEM'
        }
        It 'returns null for an unresolvable SID' {
            Convert-SidToAccount -Sid 'S-1-5-21-0-0-0-0' | Should -BeNullOrEmpty
        }
    }

    Context 'ConvertTo-ArgumentList' {
        It 'formats booleans as -Key:$true / -Key:$false' {
            $argList = ConvertTo-ArgumentList -InputHashtable @{ AutoBindJCUser = $true; BindAsAdmin = $false }
            $argList | Should -Contain '-AutoBindJCUser:$true'
            $argList | Should -Contain '-BindAsAdmin:$false'
        }
        It 'formats strings as -Key:Value and skips empty strings' {
            $argList = ConvertTo-ArgumentList -InputHashtable @{ JumpCloudUserName = 'jdoe'; JumpCloudOrgID = '' }
            $argList | Should -Contain '-JumpCloudUserName:jdoe'
            ($argList -join ' ') | Should -Not -Match 'JumpCloudOrgID'
        }
    }

    Context 'Start-SelfServeMigration' {
        BeforeAll {
            $target = [PSCustomObject]@{ SID = 'S-1-5-21-1-2-3-1001'; JumpCloudUserName = 'jdoe'; LocalPath = 'C:\Users\jdoe'; JumpCloudUserID = 'uid1' }
            $baseConfig = @{
                TempPassword = 'Temp123!Temp123!'; LeaveDomain = $true; ForceReboot = $true; UpdateHomePath = $false
                AutoBindJCUser = $true; BindAsAdmin = $false; SetDefaultWindowsUser = $true; systemContextBinding = $false
                removeMDM = $false; postMigrationBehavior = 'Restart'; localEXEs = $false; SetFullPermission = $false
                BlockAccountLogin = $false; bypassExeValidation = $false; DryRun = $false
            }
        }
        It 'does NOT migrate or reboot in DryRun' {
            Mock Get-LatestADMUGUIExe { 'C:\Windows\Temp\gui_jcadmu.exe' }
            Mock Restart-Computer { }
            Mock Stop-Computer { }
            $cfg = $baseConfig.Clone(); $cfg.DryRun = $true
            Start-SelfServeMigration -Target $target -Config $cfg -ApiKey 'k' | Should -Be $true
            Should -Invoke Get-LatestADMUGUIExe -Times 0
            Should -Invoke Restart-Computer -Times 0
        }
    }

    Context 'New-DeferLogonTask' {
        BeforeEach {
            # Real (offline) New-ScheduledTask* builders run; only mock the disk + registration calls.
            Mock New-Item { }
            Mock Set-Content { }
            Mock Register-ScheduledTask { }
        }
        It 'writes the staged script and registers the AtLogon reminder (fixed task name, no -User)' {
            $result = New-DeferLogonTask -ScriptContent '# self text' -DryRun $false
            $result | Should -Be $true
            Should -Invoke Set-Content -Times 1 -ParameterFilter { $LiteralPath -like '*JCADMU\selfserve.ps1' }
            Should -Invoke Register-ScheduledTask -Times 1 -ParameterFilter { $TaskName -eq 'ADMU-SelfServe-Defer' }
        }
        It 'does not stage or register in DryRun' {
            $result = New-DeferLogonTask -ScriptContent '# self text' -DryRun $true
            $result | Should -Be $true
            Should -Invoke Set-Content -Times 0
            Should -Invoke Register-ScheduledTask -Times 0
        }
        It 'returns false when the script content is empty (e.g. path and inline both unavailable)' {
            New-DeferLogonTask -ScriptContent '' -DryRun $false | Should -Be $false
        }
        It 'returns false when task registration throws' {
            Mock Register-ScheduledTask { throw "denied" }
            New-DeferLogonTask -ScriptContent '# self text' -DryRun $false | Should -Be $false
        }
    }

    Context 'New-PromptRunnerScript' {
        It 'writes a runner script that parses without errors' {
            $rp = Join-Path $env:TEMP 'admu-runner-pester.ps1'
            New-PromptRunnerScript -Path $rp
            $errs = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($rp, [ref]$null, [ref]$errs)
            $errs | Should -BeNullOrEmpty
            Remove-Item $rp -Force -ErrorAction SilentlyContinue
        }
    }
}
