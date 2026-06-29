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
        $script:providersPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
        $script:backupKey = "HKLM:\SOFTWARE\JCADMU\LoginPolicyBackup"

        $script:originalExcluded = (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders
        $script:originalCaption = (Get-ItemProperty -Path $script:regPath -Name 'legalnoticecaption' -ErrorAction SilentlyContinue).legalnoticecaption
        $script:originalText = (Get-ItemProperty -Path $script:regPath -Name 'legalnoticetext' -ErrorAction SilentlyContinue).legalnoticetext
        $script:originalProviderStates = @{}
        foreach ($provider in Get-ChildItem -Path $script:providersPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\{[0-9a-fA-F-]+\}$' }) {
            $disabled = (Get-ItemProperty -Path $provider.PSPath -Name 'Disabled' -ErrorAction SilentlyContinue).Disabled
            $script:originalProviderStates[$provider.PSChildName] = $disabled
        }
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
        foreach ($clsid in $script:originalProviderStates.Keys) {
            $providerKey = Join-Path $script:providersPath $clsid
            $disabled = $script:originalProviderStates[$clsid]
            if ($null -ne $disabled) {
                Set-ItemProperty -Path $providerKey -Name 'Disabled' -Value $disabled -Type DWord
            } else {
                Remove-ItemProperty -Path $providerKey -Name 'Disabled' -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Blocking and restoring interactive logon (registry credential providers)" {
        It "Disable excludes and disables all installed credential providers" {
            $installedProviders = @(Get-InstalledCredentialProviderClsids)
            $installedProviders.Count | Should -BeGreaterThan 0

            $result = Set-AccountLoginPolicy -SID $script:testSID -Action Disable
            $result.Success | Should -BeTrue

            $excluded = @(Get-ExcludedCredentialProviders)
            foreach ($clsid in $installedProviders) {
                $excluded | Should -Contain $clsid
                $providerKey = Join-Path $script:providersPath $clsid
                (Get-ItemProperty -Path $providerKey -Name 'Disabled').Disabled | Should -Be 1
            }
            (Get-ItemProperty -Path $script:backupKey -Name 'BlockedSid').BlockedSid | Should -Be $script:testSID
        }

        It "Enable restores the original credential-provider registry state" {
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
            foreach ($clsid in $installedProviders) {
                $providerKey = Join-Path $script:providersPath $clsid
                $currentDisabled = (Get-ItemProperty -Path $providerKey -Name 'Disabled' -ErrorAction SilentlyContinue).Disabled
                $currentDisabled | Should -Be $script:originalProviderStates[$clsid]
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
