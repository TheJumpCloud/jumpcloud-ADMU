Describe "Get-MtpOrganization Acceptance Tests" {
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
    It "Return an organization with a valid API Key" {
        # Add acceptance test logic and assertions (against a real system)
        $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
        $OrgName = "$($OrgSelection[1])"
        $OrgID = "$($OrgSelection[0])"

        $OrgName | Should -Not -BeNullOrEmpty
        $OrgID | Should -Not -BeNullOrEmpty
    }
    It "Throw when an invalid API key is provided" {
        # Add acceptance test logic and assertions (against a real system)
        { Get-MtpOrganization -apiKey "asdf" } | Should -Throw

    }

    # Add more acceptance tests as needed
}
