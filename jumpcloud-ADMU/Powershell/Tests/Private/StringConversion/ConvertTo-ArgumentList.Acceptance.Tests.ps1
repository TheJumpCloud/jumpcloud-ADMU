Describe "ConvertTo-ArgumentList Tests" -Tag "Acceptance" {
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
    Context "When converting a hashtable of ADMU parameters to an argument list" {

        It "should produce correctly formatted arguments for strings and booleans, and skip null/empty values" {
            # 1. Define a sample hashtable using your parameters with various values
            $testParams = @{
                JumpCloudUserName     = "reid.sullivan"
                SelectedUserName      = "mycorpsoft/reid.sullivan"
                TempPassword          = "P@ssw0rd123!"
                LeaveDomain           = $true
                ForceReboot           = $true
                UpdateHomePath        = $true
                InstallJCAgent        = $true
                AutoBindJCUser        = $true
                # Intentionally set some parameters to null or empty to ensure they are skipped
                JumpCloudConnectKey   = $null
                JumpCloudAPIKey       = ""
                JumpCloudOrgID        = "123456789012345678901234"
                SetDefaultWindowsUser = $true
                systemContextBinding  = $true
                ReportStatus          = $true
            }

            # 2. Run the function with the test data
            $result = ConvertTo-ArgumentList -InputHashtable $testParams

            $result = $result -join ' '
            $expectedArguments = "-JumpCloudOrgID:123456789012345678901234 -SetDefaultWindowsUser:`$true -systemContextBinding:`$true -UpdateHomePath:`$true -JumpCloudUserName:reid.sullivan -AutoBindJCUser:`$true -ForceReboot:`$true -TempPassword:P@ssw0rd123! -SelectedUserName:mycorpsoft/reid.sullivan -ReportStatus:`$true -InstallJCAgent:`$true -LeaveDomain:`$true"


            $escapedExpectedArguments = [System.Text.RegularExpressions.Regex]::Escape($expectedArguments)

            $result | Should -Match $escapedExpectedArguments
        }
    }

}
