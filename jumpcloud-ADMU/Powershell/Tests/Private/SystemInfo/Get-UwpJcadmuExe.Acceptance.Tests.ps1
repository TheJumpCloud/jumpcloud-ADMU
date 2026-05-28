Describe "Get-UwpJcadmuExe Acceptance Tests" -Tag "Acceptance" {
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

        $script:testWindowsDrive = Join-Path -Path $env:TEMP -ChildPath ("admu-get-uwp-exe-" + [guid]::NewGuid().ToString())
        $script:testWindowsDir = Join-Path -Path $script:testWindowsDrive -ChildPath "Windows"
        $script:testExePath = Join-Path -Path $script:testWindowsDir -ChildPath "uwp_jcadmu.exe"
        New-Item -Path $script:testWindowsDir -ItemType Directory -Force | Out-Null
    }

    It "Should throw when localEXEs is enabled and local executable is missing" {
        if (Test-Path -Path $script:testExePath -PathType Leaf) {
            Remove-Item -Path $script:testExePath -Force
        }

        { Get-UwpJcadmuExe -WindowsDrive $script:testWindowsDrive -localEXEs $true -MaxRetries 2 -RetryDelaySeconds 1 } |
        Should -Throw -ExpectedMessage "localEXEs is enabled, but required file 'uwp_jcadmu.exe' was not found at '$script:testExePath'."
    }

    It "Should download the latest executable when localEXEs is disabled" {
        if (Test-Path -Path $script:testExePath -PathType Leaf) {
            Remove-Item -Path $script:testExePath -Force
        }

        $resultPath = Get-UwpJcadmuExe -WindowsDrive $script:testWindowsDrive -localEXEs $false -MaxRetries 3 -RetryDelaySeconds 1

        $resultPath | Should -Be $script:testExePath
        Test-Path -Path $resultPath -PathType Leaf | Should -BeTrue
    }

    It "Should use the local executable when localEXEs is enabled" {
        if (-not (Test-Path -Path $script:testExePath -PathType Leaf)) {
            $null = Get-UwpJcadmuExe -WindowsDrive $script:testWindowsDrive -localEXEs $false -MaxRetries 3 -RetryDelaySeconds 1
        }

        $resultPath = Get-UwpJcadmuExe -WindowsDrive $script:testWindowsDrive -localEXEs $true -MaxRetries 3 -RetryDelaySeconds 1

        $resultPath | Should -Be $script:testExePath
        Test-Path -Path $resultPath -PathType Leaf | Should -BeTrue
    }

    It "Should return null when retries are disabled and download is not attempted" {
        if (Test-Path -Path $script:testExePath -PathType Leaf) {
            Remove-Item -Path $script:testExePath -Force
        }

        $resultPath = Get-UwpJcadmuExe -WindowsDrive $script:testWindowsDrive -localEXEs $false -MaxRetries 0 -RetryDelaySeconds 0

        $resultPath | Should -BeNullOrEmpty
        Test-Path -Path $script:testExePath -PathType Leaf | Should -BeFalse
    }

    AfterAll {
        if (Test-Path -Path $script:testWindowsDrive) {
            Remove-Item -Path $script:testWindowsDrive -Recurse -Force
        }
    }
}
