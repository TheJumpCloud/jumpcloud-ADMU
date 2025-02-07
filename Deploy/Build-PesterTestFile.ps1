Function Build-PesterTestFile {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.String]
        $ProjectRoot = "$PSScriptRoot/../JumpCloud-ADMU",
        [Parameter()]
        [ValidateSet("Unit", "Acceptance", "All")]
        [string]
        $TestType = "All", # Default to generate both types of tests
        [Parameter()]
        [switch]
        $Force # Force overwrite of existing test files
    )
    begin {
        $testsDirectory = Join-Path $ProjectRoot "PowerShell/Tests"
        if (!(Test-Path $testsDirectory)) {
            New-Item -ItemType Directory -Force -Path $testsDirectory
        }
        $publicPath = Join-Path $ProjectRoot "/PowerShell/Public" -Resolve
        $privatePath = Join-Path $ProjectRoot "/PowerShell/Private" -Resolve

        $functions = Get-ChildItem -Path $publicPath, $privatePath -Recurse -Filter "*.ps1"

        # loaded functions =
        $defaultFunctions = Get-Command -Module Microsoft.PowerShell.Utility
    }
    process {
        foreach ($function in $functions) {
            $functionType = if ($function.FullName -match "PowerShell/Public") { "Public" } else { "Private" }
            $relativePath = $function.FullName -replace "^.*PowerShell/(Public|Private)/", ""
            $relativePath = Split-Path -Path $relativePath -Parent

            $testDir = Join-Path $testsDirectory $functionType $relativePath
            if (!(Test-Path $testDir)) { New-Item -ItemType Directory -Force -Path $testDir }

            # Generate Unit Test File
            if ($TestType -in "Unit", "All") {
                $unitTestName = ($function.BaseName) + ".Unit.Tests.ps1"
                $unitTestPath = Join-Path $testDir $unitTestName

                if ($Force -or !(Test-Path $unitTestPath)) {
                    # Check for -Force or if file doesn't exist
                    $functionContent = Get-Content $function.FullName -Raw
                    $calledFunctions = [regex]::Matches($functionContent, "(?<=[\s\.])([a-zA-Z-]+\-[a-zA-Z-]+)") | ForEach-Object { $_.Groups.Value } | Sort-Object -Unique
                    $customFunctions = $calledFunctions | Where-Object { ($_ -notin $defaultFunctions.Name) -AND ( $_ -ne $function.BaseName ) }

                    $mockFunctions = ""
                    foreach ($calledFunction in $customFunctions) {
                        $mockFunctions += @"
    function $calledFunction {
        [CmdletBinding()]
        param()
        process {
            # Mock implementation for $calledFunction
            Write-Host "Mocked $calledFunction" # Replace with appropriate mock behavior
        }
    }
"@
                    }

                    $unitTestContent = @"
Describe "$($function.BaseName) Unit Tests" {
    BeforeAll {
        # import the function
        `$functionPath = (`$PSCommandPath.Replace('.Unit.Tests.ps1', '.ps1')) -replace '\/Tests\/|\\Tests\\', '/'
        . `$functionPath
        $mockFunctions
    }

    It "Should..." {
        # Add unit test logic and assertions
    }

    # Add more unit tests as needed
}
"@
                    $unitTestContent | Out-File -FilePath $unitTestPath -Force
                }
            }

            # Generate Acceptance Test File
            if ($TestType -in "Acceptance", "All") {
                $acceptanceTestName = ($function.BaseName) + ".Acceptance.Tests.ps1"
                $acceptanceTestPath = Join-Path $testDir $acceptanceTestName

                if ($Force -or !(Test-Path $acceptanceTestPath)) {
                    # Check for -Force or if file doesn't exist
                    $acceptanceTestContent = @"
Describe "$($function.BaseName) Acceptance Tests" {
    BeforeAll {
        # import all functions
        `$currentPath = `$PSScriptRoot # Start from the current script's directory.
        `$TargetDirectory = "helperFunctions"
        `$FileName = "Import-AllFunctions.ps1"
        while (`$currentPath -ne `$null) {
            `$filePath = Join-Path -Path `$currentPath `$TargetDirectory `$FileName
            if (Test-Path `$filePath) {
                # File found! Return the full path.
                `$helpFunctionDir = `$filePath
                break
            }

            # Move one directory up.
            `$currentPath = Split-Path `$currentPath -Parent
        }
      . "`$helpFunctionDir"
    }
    It "Should..." {
        # Add acceptance test logic and assertions (against a real system)
    }

    # Add more acceptance tests as needed
}
"@
                    $acceptanceTestContent | Out-File -FilePath $acceptanceTestPath -Force
                }
            }
        }
    }
    end {

    }
}