Describe "Test-SkipMdmEnrollment Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($null -ne $currentPath) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$FileName"
    }

    It "Returns true when enrollment ProviderID contains JumpCloud in registry" {
        $guid = [guid]::NewGuid().ToString()
        $regPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$guid"
        New-Item -Path $regPath -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name "ProviderID" -Value "JumpCloud MDM"
        try {
            Test-SkipMdmEnrollment -EnrollmentGUID $guid | Should -Be $true
        } finally {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It "Returns true when enrollment ProviderID contains JumpCloud in enrollments list" {
        $guid = [guid]::NewGuid().ToString()
        $enrollments = @(
            [PSCustomObject]@{
                EnrollmentGUID = $guid
                ProviderID     = "SomeJumpCloudProvider"
                UPN            = "user@example.com"
            }
        )
        Test-SkipMdmEnrollment -EnrollmentGUID $guid -Enrollments $enrollments | Should -Be $true
    }

    It "Returns false for non-JumpCloud enrollment" {
        $guid = [guid]::NewGuid().ToString()
        $enrollments = @(
            [PSCustomObject]@{
                EnrollmentGUID = $guid
                ProviderID     = "MS DM Server"
                UPN            = "user@example.com"
            }
        )
        Test-SkipMdmEnrollment -EnrollmentGUID $guid -Enrollments $enrollments | Should -Be $false
    }
}
