Describe "Set-JcUrl Acceptance Tests" -Tag "Acceptance" {
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
    It "Set JCUrl to US region" {
        Set-JcUrl -Region "US"
        $global:JCUrl | Should -Be "https://console.jumpcloud.com"
    }
    It "Set JCUrl to EU region" {
        Set-JcUrl -Region "EU"
        $global:JCUrl | Should -Be "https://console.eu.jumpcloud.com"
    }
}
