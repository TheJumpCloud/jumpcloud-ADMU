Describe "Get-UwpJcadmuReleaseInfo Acceptance Tests" -Tag "Acceptance" {
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

    It "Should return the latest UWP release metadata" {
        $result = Get-UwpJcadmuReleaseInfo -MaxRetries 3 -RetryDelaySeconds 1

        $result.GetType().Name | Should -Be 'PSCustomObject'
        $result.TagName | Should -Match '^v'
        $result.Version | Should -Not -BeNullOrEmpty
        $result.SHA256 | Should -Match '^[a-fA-F0-9]{64}$'
        $result.DownloadUrl | Should -Match '^https://github.com/TheJumpCloud/jumpcloud-ADMU/releases/(latest/download|download/v[^/]+)/uwp_jcadmu\.exe$'
    }

    It "Should return consistent release metadata across consecutive calls" {
        $resultA = Get-UwpJcadmuReleaseInfo -MaxRetries 3 -RetryDelaySeconds 1
        $resultB = Get-UwpJcadmuReleaseInfo -MaxRetries 3 -RetryDelaySeconds 1

        $resultA.TagName | Should -Be $resultB.TagName
        $resultA.Version | Should -Be $resultB.Version
        $resultA.SHA256 | Should -Be $resultB.SHA256
        $resultA.DownloadUrl | Should -Be $resultB.DownloadUrl
    }

    It "Should return no release metadata when MaxRetries is zero" {
        $result = Get-UwpJcadmuReleaseInfo -MaxRetries 0 -RetryDelaySeconds 0

        $result | Should -BeNullOrEmpty
    }
}