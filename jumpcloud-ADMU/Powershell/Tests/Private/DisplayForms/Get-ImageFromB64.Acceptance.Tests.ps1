Describe "Get-ImageFromB64 Acceptance Tests" -Tag "Acceptance" {
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

        # load the necessary form types
        $types = @(
            'PresentationFramework',
            'PresentationCore',
            'System.Windows.Forms',
            'System.Drawing',
            'WindowsBase'
        )
        foreach ($type in $types) {
            if (-not ([System.Management.Automation.PSTypeName]$type).Type) {
                [void][System.Reflection.Assembly]::LoadWithPartialName($type)
                Add-Type -AssemblyName $type
            }
        }
    }
    It "Should not throw when converting b64 string to image" {
        # dot source the images file
        . Join-Path "$PSScriptRoot" "/../DisplayAssets/Images.ps1"
        # convert the image
        { Get-ImageFromB64 -ImageBase64 $BlueBase64 } | Should -Not -Throw
    }

    # Add more acceptance tests as needed
}
