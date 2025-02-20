Describe "Test-JumpCloudUsername Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        Write-Host "#####Starting Test-JumpCloudUsername Acceptance Tests"
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

        Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -Force

    }
    It 'Valid Username Returns True' {
        # Get the first user
        $user = Get-JcSdkUser | Select-Object -First 1
        # Test username w/o modification
        $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $user.Username
        $testResult | Should -Be $true
        $userID | Should -Be $user.Id
        # toUpper
        $upper = ($user.Username).ToUpper()
        $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $upper
        $testResult | Should -Be $true
        $userID | Should -Be $user.Id
        # to lower
        $lower = ($user.Username).ToLower()
        $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $lower
        $testResult | Should -Be $true
        $userID | Should -Be $user.Id
    }
    It 'Invalid Username Returns False' {
        # Get the first user
        $user = Get-JcSdkUser | Select-Object -First 1
        # Append random string to username
        $newUsername = $user.Username + "jdksf45kjfds"
        # Test function
        $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $newUsername
        $testResult | Should -Be $false
        $userID | Should -Be $null
    }

    # Add more acceptance tests as needed
}
