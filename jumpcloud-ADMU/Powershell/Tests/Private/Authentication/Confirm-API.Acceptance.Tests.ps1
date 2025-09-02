Describe "Confirm API Key Acceptance Tests" -Tag "Acceptance" {
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
}
Describe "Confirm API Key Acceptance Tests" -Tag "InstallJC" {
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

        $config = get-content 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
    }
    It "Should get the system endpoint on a device eligible to use the systemContext API" {
        $response = Invoke-SystemContextAPI -method "GET" -endpoint "systems"
        $response.id | Should -Not -BeNullOrEmpty
    }

    Context "Function tests" {

        It "Should return valid system key and should be valid if systemContextBinding is true" {
            $results = Confirm-API -SystemContextBinding $true
            $results.type | Should -Be "SystemContext"
            $results.valid | Should -Be $true
            $results.validatedSystemID | Should -Be $systemKey
        }

        It "Should return valid system key and should be valid when API key is present and systemContextBinding is false" {
            $results = Confirm-API -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -SystemContextBinding $false
            $results.type | Should -Be "API"
            $results.valid | Should -Be $true
            $results.validatedSystemID | Should -Be $systemKey
        }
        It "Should fail with invalid API KEY" {
            $results = Confirm-API -JumpCloudApiKey "invalid_key" -JumpCloudOrgId $env:PESTER_ORGID -SystemContextBinding $false
            $results.type | Should -Be "API"
            $results.valid | Should -Be $false
            $results.validatedSystemID | Should -Be $null
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
