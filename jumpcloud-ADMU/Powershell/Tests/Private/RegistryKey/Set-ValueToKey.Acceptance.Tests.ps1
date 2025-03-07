Describe "Set-ValueToKey Acceptance Tests" -Tag "Acceptance" {
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
    It "Should Set-ValueToKey" {
        Set-ValueToKey -registryRoot LocalMachine -keyPath 'SYSTEM\Software' -name '1' -value '1' -regValueKind DWord
        Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\Software\' -Name '1' | Should -Be '1'
    }

    # Add more acceptance tests as needed
}
