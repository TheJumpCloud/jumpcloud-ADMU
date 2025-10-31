Describe "Get-MtpOrganization Acceptance Tests" -Tag "Acceptance" {
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
    Context "Get-MtpOrganization Function Tests" {
        It "Should return an organization with a valid API Key" {
            # Add acceptance test logic and assertions (against a real system)
            $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
            Write-Host "org selection: $OrgSelection"
            $OrgName = "$($OrgSelection[1])"
            $OrgID = "$($OrgSelection[0])"

            $OrgName | Should -Not -BeNullOrEmpty
            $OrgID | Should -Not -BeNullOrEmpty
            $MTPAdmin | Should -Be $false
        }
        It "Should return an organization with a valid API Key and OrgID" {
            # Add acceptance test logic and assertions (against a real system)
            $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY -orgID $env:PESTER_ORGID
            Write-Host "org selection: $OrgSelection"
            $OrgName = "$($OrgSelection[1])"
            $OrgID = "$($OrgSelection[0])"

            $OrgName | Should -Not -BeNullOrEmpty
            $OrgID | Should -Not -BeNullOrEmpty
            $MTPAdmin | Should -Be $false
        }
        It "Should throw when an invalid API key is provided, expecting 401 Unauthorized" {
            { Get-MtpOrganization -apiKey "asdf" } | Should -Throw -ExpectedMessage { "*401 (Unauthorized)*" }
        }
        It "Should throw when an empty API key is provided" {
            { Get-MtpOrganization -apiKey "" } | Should -Throw -ExpectedMessage "*because it is an empty string*"
        }
    }
    Context "Get-MtpOrganization Function MTP Tests" {
        It "Should throw when a valid MTP API key is provided but an invalid OrgID is provided, expecting 404 Not Found" -Skip {
            # TODO: Skipping until we add EU MTP API Key & Compatible PWSH Modules CUT-4958
            { Get-MtpOrganization -apiKey $env:PESTER_MTP_APIKEY -orgID "invalid-org-id" } | Should -Throw -ExpectedMessage { "*404 (Not Found)*" }
        }
        It "Should return an organization when a MTP API key is provided and a valid OrgID is provided" -Skip {
            # TODO: Skipping until we add EU MTP API Key & Compatible PWSH Modules CUT-4958
            $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_MTP_APIKEY -orgID $env:PESTER_MTP_ORGID
            Write-Host "org selection: $OrgSelection"
            $OrgName = "$($OrgSelection[1])"
            $OrgID = "$($OrgSelection[0])"

            $OrgName | Should -Not -BeNullOrEmpty
            $OrgID | Should -Not -BeNullOrEmpty
            $MTPAdmin | Should -Be $true
        }
    }


}
