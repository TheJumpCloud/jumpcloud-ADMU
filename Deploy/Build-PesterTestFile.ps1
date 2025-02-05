Function Build-PesterTestFile {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.String]
        $ProjectRoot = "$PSScriptRoot/../jumpcloud-ADMU"
    )
    begin {
        # Create the Tests directory if it doesn't exist
        $testsDirectory = Join-Path "$ProjectRoot" "/Powershell/Tests"
        if (!(Test-Path $testsDirectory)) {
            New-Item -ItemType Directory -Force -Path $testsDirectory
        }
        # Create the Public Tests directory if it doesn't exist
        $publicTestsDirectory = Join-Path "$ProjectRoot" "/Powershell/Tests/Public"
        if (!(Test-Path $publicTestsDirectory)) {
            New-Item -ItemType Directory -Force -Path $publicTestsDirectory
        }
        # Create the Private Tests directory if it doesn't exist
        $privateTestsDirectory = Join-Path "$ProjectRoot" "/Powershell/Tests/Private"
        if (!(Test-Path $privateTestsDirectory)) {
            New-Item -ItemType Directory -Force -Path $privateTestsDirectory
        }
        # get all functions
        $functionsDir = "$ProjectRoot/Powershell/"
        $functions = New-Object System.Collections.ArrayList
        $publicFunctions = Get-ChildItem -Path "$functionsDir/Public" -Recurse -Filter "*.ps1"
        $privateFunctions = Get-ChildItem -Path "$functionsDir/Private" -Recurse -Filter "*.ps1"
        $privateFunctions | ForEach-Object { $functions.Add($_) | Out-Null }
        $publicFunctions | ForEach-Object { $functions.Add($_) | Out-Null }
        # $functions =

    }
    process {
        $directories = @("Public", "Private")

        foreach ($function in $functions) {
            # where did the function come from public or private
            $functionType = switch ($function.FullName) {
                { $_ -match "Powershell/Public" } {
                    "Public"
                }
                { $_ -match "Powershell/Private" } {
                    "Private"
                }
            }

            # recurse back to get full file path:
            $filePath = $function.FullName
            $parentString = ""
            do {
                # get the parent of the filePath
                $parent = (Get-Item (Split-Path -Path $filePath -Parent)).name
                $parentString += "/$parent"
            }
            until (($parent = "Public") -or ($parent = "Private"))
            $testName = $($function.Name) -replace ('.ps1', '.Tests.ps1')

            # create the public/ private tests dirs
            $functionTestDirPath = Join-Path $testsDirectory $functionType
            if (!(Test-Path $functionTestDirPath)) {
                New-Item -ItemType Directory -Force -Path $functionTestDirPath
            }
            # if there's a subfolder create that
            if (($parentString -ne "Public") -or ($parentString -ne "Private")) {
                $functionTestSubPath = Join-Path $functionTestDirPath $parentString
                if (!(Test-Path $functionTestSubPath)) {
                    New-Item -ItemType Directory -Force -Path $functionTestSubPath
                }
            } else {
                $functionTestSubPath = $functionTestDirPath
            }
            # create the test file
            $functionTestFullPath = Join-Path $functionTestSubPath $testName
            if (!(Test-Path $functionTestFullPath)) {
                New-Item -ItemType File -Force -Path $functionTestFullPath
                $testFileContent = @"
Describe "$($function.BaseName) Tests" {
    BeforeAll {
        # import the function
        try {
            `$functionPath = (`$PSCommandPath.Replace('.Tests.ps1', '.ps1')) -replace '\/Tests\/|\\Tests\\', '/'
            . `$functionPath
        } catch {
            Write-Error "Could not import `$functionPath"
        }
    }
}
"@
                # write the file
                $testFileContent | Out-File -FilePath $functionTestFullPath -Force
            }
        }
    }
    end {

    }
}


Build-PesterTestFile