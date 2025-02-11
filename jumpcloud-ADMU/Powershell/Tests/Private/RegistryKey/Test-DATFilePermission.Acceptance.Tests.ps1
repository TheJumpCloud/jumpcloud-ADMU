Describe "Test-DATFilePermission Acceptance Tests" -Tag "Acceptance" {
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

    It "Should Test NTFS DAT File Permission" {

        # Test NTFS NTUser dat permissions
        $NTUser, $permissionHash = Test-DATFilePermission -Path "C:\Users\$($env:USERNAME)\NTUSER.DAT" -username $($env:USERNAME) -type 'ntfs'

        # Validate NTFS Permissions
        $NTUser | Should -Be $true
        $permissionHash | Should -Not -BeNullOrEmpty
    }

    It "Should Test UsrClass DAT File Permission" {
        # Test NTFS UsrClass dat permissions
        $UsrClass, $permissionHash = Test-DATFilePermission -Path "C:\Users\$($env:USERNAME)\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $($env:USERNAME) -type 'ntfs'

        # Validate NTFS Permissions
        $UsrClass | Should -Be $true
        $permissionHash | Should -Not -BeNullOrEmpty

    }
    # Add more acceptance tests as needed
}
