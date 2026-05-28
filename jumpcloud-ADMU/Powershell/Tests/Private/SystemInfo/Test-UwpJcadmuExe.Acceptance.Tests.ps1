Describe "Test-UwpJcadmuExe Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $targetDirectory = "helperFunctions"
        $fileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath -ChildPath $targetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }

            $currentPath = Split-Path $currentPath -Parent
        }

        . "$helpFunctionDir\$fileName"
    }

    It "Should throw when the target file does not exist" {
        $missingPath = Join-Path -Path $env:WINDIR -ChildPath 'uwp_jcadmu.exe'
        if (Test-Path -Path $missingPath -PathType Leaf) {
            Remove-Item -Path $missingPath -Force
        }

        { Test-UwpJcadmuExe -FilePath $missingPath } | Should -Throw -ExpectedMessage "File not found: '$missingPath'."
    }

    It "Should return a real validation result for an existing executable" {
        $releaseInfo = Get-UwpJcadmuReleaseInfo -MaxRetries 3 -RetryDelaySeconds 1
        $downloadedExePath = Join-Path -Path $env:TEMP -ChildPath 'uwp_jcadmu.acceptance.exe'

        try {
            Invoke-WebRequest -Uri $releaseInfo.DownloadUrl -OutFile $downloadedExePath -UseBasicParsing -ErrorAction Stop
            Test-Path -Path $downloadedExePath -PathType Leaf | Should -BeTrue

            $result = Test-UwpJcadmuExe -FilePath $downloadedExePath -MaxRetries 3 -RetryDelaySeconds 1 -AllowUnvalidatedOnApiFailure $false

            $result.GetType().Name | Should -Be 'PSCustomObject'
            $result.FilePath | Should -Be $downloadedExePath
            $result.ReleaseTag | Should -Not -BeNullOrEmpty
            $result.ReleaseVersion | Should -Not -BeNullOrEmpty
            $result.HashMatched | Should -BeTrue
            $result.IsValid | Should -BeTrue
            $result.UsedWithoutValidation | Should -BeFalse
            $result.ValidationWarning | Should -BeNullOrEmpty
        } finally {
            if (Test-Path -Path $downloadedExePath -PathType Leaf) {
                Remove-Item -Path $downloadedExePath -Force
            }
        }
    }

    It "Should allow unvalidated use when release lookup fails and fallback is enabled" {
        $realExePath = Join-Path -Path $env:WINDIR -ChildPath 'System32\notepad.exe'
        Test-Path -Path $realExePath -PathType Leaf | Should -BeTrue

        $result = Test-UwpJcadmuExe -FilePath $realExePath -MaxRetries 0 -RetryDelaySeconds 0 -AllowUnvalidatedOnApiFailure $true

        $result.IsValid | Should -BeTrue
        $result.UsedWithoutValidation | Should -BeTrue
        $result.HashMatched | Should -BeFalse
        $result.ReleaseTag | Should -BeNullOrEmpty
        $result.ValidationWarning | Should -Not -BeNullOrEmpty
    }

    It "Should throw when release lookup fails and fallback is disabled" {
        $realExePath = Join-Path -Path $env:WINDIR -ChildPath 'System32\notepad.exe'
        Test-Path -Path $realExePath -PathType Leaf | Should -BeTrue

        { Test-UwpJcadmuExe -FilePath $realExePath -MaxRetries 0 -RetryDelaySeconds 0 } | Should -Throw -ExpectedMessage 'Failed to validate UWP executable*'
    }
}