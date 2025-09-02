Describe "Confirm API Key Acceptance Tests" -Tag "InstallJC" {
    BeforeAll {
        $env:PESTER_APIKEY = "jca_8Ndq2u7BCUtxarcdWCeFKrdaG6h4GcAQavnJ"
        $env:PESTER_ORGID = "61e9dca26172a32c8a77c5b3"
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

        $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    }

    Context "Function tests" {

        It "Should return $true and systemId with valid API key and Agent" {
            $isValid, $systemId = Test-ApiKey -ApiKey $env:PESTER_APIKEY -OrgId $env:PESTER_ORGID
            $isValid | Should -Be $true
            $systemId | Should -Be $systemKey
        }
        It "Should return $false and systemId with valid API key and Agent" {
            $isValid, $systemId = Test-ApiKey -ApiKey "Invalid" -OrgId $env:PESTER_ORGID
            $isValid | Should -Be $false
            $systemId | Should -Be $null
        }
        AfterAll {
            # for local testing this can be enabled:
            # $usersToRemove = Get-JCSdkUser | Where-Object { $_.email -match "@jumpcloudadmu.com" }
            # foreach ($user in $usersToRemove) {
            #     # If User Exists, remove from the org
            #     Remove-JcSdkUser -Id $user.Id | Out-Null
            # }
        }
    }

    # Add more acceptance tests as needed
}
