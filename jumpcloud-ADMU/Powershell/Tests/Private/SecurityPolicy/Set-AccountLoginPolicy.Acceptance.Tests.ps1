Describe "Set-AccountLoginPolicy Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"

        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }

        . "$helpFunctionDir\$FileName"

        $script:testSID = "S-1-5-21-1111111111-2222222222-3333333333-65500"
        $script:regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $script:backupKey = "HKLM:\SOFTWARE\JCADMU\LoginPolicyBackup"

        $script:originalExcluded = (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders
        $script:originalCaption = (Get-ItemProperty -Path $script:regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
        $script:originalText = (Get-ItemProperty -Path $script:regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
    }

    AfterEach {
        $null = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
        if (Test-Path $script:backupKey) {
            Remove-Item -Path $script:backupKey -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        if ($null -ne $script:originalExcluded) {
            Set-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -Value $script:originalExcluded -Type String
        } else {
            Remove-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue
        }
        if ($null -ne $script:originalCaption) {
            Set-ItemProperty -Path $script:regPath -Name 'legalnoticecaption' -Value $script:originalCaption -Type String
        } else {
            Remove-ItemProperty -Path $script:regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue
        }
        if ($null -ne $script:originalText) {
            Set-ItemProperty -Path $script:regPath -Name 'legalnoticetext' -Value $script:originalText -Type String
        } else {
            Remove-ItemProperty -Path $script:regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue
        }
    }

    Context "Blocking and restoring interactive logon (registry credential providers)" {
        It "Disable excludes all installed credential providers" {
            $installedProviders = @(Get-InstalledCredentialProviderClsids)
            $installedProviders.Count | Should -BeGreaterThan 0

            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $result.Success | Should -BeTrue

            $excluded = @(Get-ExcludedCredentialProviders)
            foreach ($clsid in $installedProviders) {
                $excluded | Should -Contain $clsid
            }
            (Get-ItemProperty -Path $script:backupKey -Name 'BlockedSid').BlockedSid | Should -Be $script:testSID
        }

        It "Enable restores the original ExcludedCredentialProviders registry state" {
            $installedProviders = @(Get-InstalledCredentialProviderClsids)
            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable

            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
            $result.Success | Should -BeTrue

            Test-Path $script:backupKey | Should -BeFalse
            if ($null -eq $script:originalExcluded) {
                (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders | Should -BeNullOrEmpty
            } else {
                (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders').ExcludedCredentialProviders | Should -Be $script:originalExcluded
            }
        }

        It "Disable is idempotent and preserves the original backup" {
            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $firstBackup = Get-ItemProperty -Path $script:backupKey

            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $secondBackup = Get-ItemProperty -Path $script:backupKey

            $secondBackup.BlockedSid | Should -Be $firstBackup.BlockedSid
            $secondBackup.excludedProvidersExisted | Should -Be $firstBackup.excludedProvidersExisted
            if ($firstBackup.excludedProvidersExisted -eq 1) {
                $secondBackup.ExcludedCredentialProviders | Should -Be $firstBackup.ExcludedCredentialProviders
            }
        }

        It "Enable on a host that is not blocked is a safe no-op" {
            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
            $result.Success | Should -BeTrue
            Test-Path $script:backupKey | Should -BeFalse
        }

        It "Disable rolls back ExcludedCredentialProviders when a later step fails" {
            $failureTitle = "Simulated failure title"

            Mock Set-ItemProperty -MockWith {
                param($Path, $Name, $Value, $Type)
                if ($Name -eq 'legalnoticecaption' -and $Value -eq $using:failureTitle) {
                    throw "Simulated failure setting legal notice"
                }
                Microsoft.PowerShell.Management\Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
            }

            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Disable -Message "body" -MessageTitle $failureTitle
            $result.Success | Should -BeFalse
            Test-Path $script:backupKey | Should -BeFalse

            if ($null -eq $script:originalExcluded) {
                (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders | Should -BeNullOrEmpty
            } else {
                (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders').ExcludedCredentialProviders | Should -Be $script:originalExcluded
            }
        }
    }

    Context "Interactive logon message (legal notice)" {
        It "Disable with a message sets the registry-backed legal notice and creates a backup" {
            $title = "Test Migration Title"
            $body = "Test migration message body."

            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Disable -Message $body -MessageTitle $title
            $result.Success | Should -BeTrue

            (Get-ItemProperty -Path $script:regPath -Name 'legalnoticecaption').legalnoticecaption | Should -Be $title
            (Get-ItemProperty -Path $script:regPath -Name 'legalnoticetext').legalnoticetext | Should -Be $body
            Test-Path $script:backupKey | Should -BeTrue
        }

        It "Enable restores the original legal notice and removes the backup key" {
            $title = "Test Migration Title"
            $body = "Test migration message body."

            $null = Set-AccountLoginPolicy -SID $script:testSID -Action Disable -Message $body -MessageTitle $title
            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Enable
            $result.Success | Should -BeTrue

            Test-Path $script:backupKey | Should -BeFalse

            $currentCaption = (Get-ItemProperty -Path $script:regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
            $currentText = (Get-ItemProperty -Path $script:regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
            $currentCaption | Should -Be $script:originalCaption
            $currentText | Should -Be $script:originalText
        }
    }
}
