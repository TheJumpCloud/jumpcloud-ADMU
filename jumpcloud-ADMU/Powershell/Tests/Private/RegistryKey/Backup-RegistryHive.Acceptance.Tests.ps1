Describe "Backup-RegistryHive Acceptance Tests" -Tag "Acceptance" {
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
    }
    Context "Backup-RegistryHive logging" {
        BeforeEach {
            $script:profilePath = 'C:\Users\testuser'
            $script:testSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
            $script:copyCalls = 0
            Mock Convert-SecurityIdentifier -MockWith { return 'DOMAIN\testuser' }
            Mock Get-ProcessByOwner -MockWith { return $null }
            Mock Show-ProcessListResult -MockWith {}
            Mock Write-AdmuErrorMessage -MockWith {}
            Mock Start-Sleep -MockWith {}
            Mock Write-ToLog -MockWith {}
        }

        It "Copies both registry hives and logs no failure when the copy succeeds" {
            Mock Copy-Item -MockWith {}

            { Backup-RegistryHive -profileImagePath $profilePath -SID $testSid } | Should -Not -Throw

            Should -Invoke Copy-Item -Exactly 2 -Scope It
            Should -Invoke Write-ToLog -Exactly 0 -Scope It
        }

        It "Never passes a null or empty Message to Write-ToLog when both attempts fail" {
            Mock Copy-Item -MockWith { throw 'Simulated access denied' }

            { Backup-RegistryHive -profileImagePath $profilePath -SID $testSid } | Should -Throw "Could Not Backup Registry Hives in $profilePath*"

            Should -Invoke Write-ToLog -Exactly 0 -Scope It -ParameterFilter { [string]::IsNullOrEmpty($Message) }
        }

        It "Logs the exception text, source path and destination path on the first attempt" {
            Mock Copy-Item -MockWith { throw 'Simulated access denied' }

            { Backup-RegistryHive -profileImagePath $profilePath -SID $testSid } | Should -Throw

            Should -Invoke Write-ToLog -Exactly 1 -Scope It -ParameterFilter {
                $Message -like "Initial backup of '$profilePath\NTUSER.DAT' to '$profilePath\NTUSER.DAT.BAK' failed: Simulated access denied"
            }
        }

        It "Logs the exception text, source path and destination path on the retry" {
            Mock Copy-Item -MockWith { throw 'Simulated access denied' }

            { Backup-RegistryHive -profileImagePath $profilePath -SID $testSid } | Should -Throw

            Should -Invoke Write-ToLog -Exactly 1 -Scope It -ParameterFilter {
                $Message -like "Retry backup of '$profilePath\NTUSER.DAT' to '$profilePath\NTUSER.DAT.BAK' failed: Simulated access denied"
            }
        }

        It "Names the UsrClass.dat hive when that copy is the one that fails" {
            Mock Copy-Item -MockWith {
                if ($Path -like '*UsrClass.dat') { throw 'Simulated UsrClass failure' }
            }

            { Backup-RegistryHive -profileImagePath $profilePath -SID $testSid } | Should -Throw

            Should -Invoke Write-ToLog -Exactly 1 -Scope It -ParameterFilter {
                $Message -like "Initial backup of '$profilePath\AppData\Local\Microsoft\Windows\UsrClass.dat' to '$profilePath\AppData\Local\Microsoft\Windows\UsrClass.dat.bak' failed: Simulated UsrClass failure"
            }
        }

        It "Does not throw when the retry succeeds, and still logs the first failure" {
            Mock Copy-Item -MockWith {
                $script:copyCalls++
                if ($script:copyCalls -eq 1) { throw 'Simulated transient lock' }
            }

            { Backup-RegistryHive -profileImagePath $profilePath -SID $testSid } | Should -Not -Throw

            # 1 failed copy, then both hives copied on the retry
            Should -Invoke Copy-Item -Exactly 3 -Scope It
            Should -Invoke Write-ToLog -Exactly 1 -Scope It -ParameterFilter {
                $Message -like "Initial backup of*failed: Simulated transient lock"
            }
            Should -Invoke Write-AdmuErrorMessage -Exactly 0 -Scope It
        }
    }
}
