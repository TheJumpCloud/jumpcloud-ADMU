Describe "Get-InstalledCredentialProviderClsids Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"

        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }

        . "$helpFunctionDir\$FileName"
        $script:providersPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"
    }

    It "Returns installed credential provider CLSIDs from the registry" {
        $result = @(Get-InstalledCredentialProviderClsids)
        $result.Count | Should -BeGreaterThan 0
        foreach ($clsid in $result) {
            $clsid | Should -Match '^\{[0-9a-fA-F-]+\}$'
            Test-Path (Join-Path $script:providersPath $clsid) | Should -BeTrue
        }
    }
}

Describe "Get-ExcludedCredentialProviders and Set-ExcludedCredentialProviders Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"

        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }

        . "$helpFunctionDir\$FileName"
        $script:regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $script:originalExcluded = (Get-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders
    }

    AfterAll {
        if ($null -ne $script:originalExcluded) {
            Set-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -Value $script:originalExcluded -Type String
        } else {
            Remove-ItemProperty -Path $script:regPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue
        }
    }

    It "Sets and reads ExcludedCredentialProviders from Policies\System" {
        $clsids = @(Get-InstalledCredentialProviderClsids | Select-Object -First 2)
        $clsids.Count | Should -BeGreaterThan 0

        Set-ExcludedCredentialProviders -Clsids $clsids -RegPath $script:regPath
        @(Get-ExcludedCredentialProviders -RegPath $script:regPath) | Should -Be $clsids

        Set-ExcludedCredentialProviders -Clsids @() -RegPath $script:regPath
        @(Get-ExcludedCredentialProviders -RegPath $script:regPath).Count | Should -Be 0
    }
}
