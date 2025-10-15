Describe "Set-HKEYUsersMount Acceptance Tests" -Tag "Acceptance" {
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
    BeforeEach {
        # Clean up any existing HKEY_USERS drive before each test
        if ("HKEY_USERS" -in (Get-PSDrive | Select-Object -ExpandProperty Name)) {
            Remove-PSDrive -Name "HKEY_USERS" -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        # Ensure HKEY_USERS drive is available after tests (restore normal state)
        if ("HKEY_USERS" -notin (Get-PSDrive | Select-Object -ExpandProperty Name)) {
            New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
        }
    }

    It "Should create HKEY_USERS drive when it doesn't exist" {
        # Arrange: Verify drive doesn't exist
        "HKEY_USERS" | Should -Not -BeIn (Get-PSDrive | Select-Object -ExpandProperty Name)

        # Act: Call the function
        Set-HKEYUserMount

        # Assert: Verify drive was created
        "HKEY_USERS" | Should -BeIn (Get-PSDrive | Select-Object -ExpandProperty Name)

        # Verify the drive properties
        $drive = Get-PSDrive -Name "HKEY_USERS"
        $drive.Provider.Name | Should -Be "Registry"
        $drive.Root | Should -Be "HKEY_USERS"
    }

    It "Should not create duplicate HKEY_USERS drive when it already exists" {
        # Arrange: Create the drive first
        New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
        $initialDriveCount = (Get-PSDrive | Where-Object { $_.Name -eq "HKEY_USERS" }).Count

        # Act: Call the function when drive already exists
        Set-HKEYUserMount

        # Assert: Verify no duplicate drives were created
        $finalDriveCount = (Get-PSDrive | Where-Object { $_.Name -eq "HKEY_USERS" }).Count
        $finalDriveCount | Should -Be $initialDriveCount
        $finalDriveCount | Should -Be 1
    }

    It "Should allow access to HKEY_USERS registry hive after mounting" {
        # Arrange: Ensure drive doesn't exist
        "HKEY_USERS" | Should -Not -BeIn (Get-PSDrive | Select-Object -ExpandProperty Name)

        # Act: Mount the drive
        Set-HKEYUserMount

        # Assert: Verify we can access the HKEY_USERS hive
        { Get-ChildItem -Path "HKEY_USERS:" -ErrorAction Stop } | Should -Not -Throw

        # Verify we can see user SIDs (there should be at least some entries)
        $userSids = Get-ChildItem -Path "HKEY_USERS:" -ErrorAction SilentlyContinue
        $userSids.Count | Should -BeGreaterThan 0
    }

    It "Should handle multiple consecutive calls without error" {
        # Act & Assert: Multiple calls should not throw errors
        { Set-HKEYUserMount } | Should -Not -Throw
        { Set-HKEYUserMount } | Should -Not -Throw
        { Set-HKEYUserMount } | Should -Not -Throw

        # Verify only one drive exists
        $driveCount = (Get-PSDrive | Where-Object { $_.Name -eq "HKEY_USERS" }).Count
        $driveCount | Should -Be 1
    }

    It "Should create a functional registry drive that can read user registry data" {
        # Arrange
        Set-HKEYUserMount

        # Act: Try to access a known registry path
        $userHives = Get-ChildItem -Path "HKEY_USERS:" -ErrorAction SilentlyContinue

        # Assert: Verify we can enumerate user hives
        $userHives | Should -Not -BeNullOrEmpty

        # Look for common SIDs (like .DEFAULT or S-1-5-* patterns)
        $defaultSid = $userHives | Where-Object { $_.PSChildName -eq ".DEFAULT" }
        $defaultSid | Should -Not -BeNullOrEmpty

        # Verify we can access a subkey within a user hive
        { Get-ItemProperty -Path "HKEY_USERS:\.DEFAULT" -ErrorAction Stop } | Should -Not -Throw
    }

    It "Should work with PowerShell registry provider cmdlets after mounting" {
        # Arrange
        Set-HKEYUserMount

        # Act & Assert: Test various registry cmdlets work with the mounted drive
        { Test-Path "HKEY_USERS:" } | Should -Not -Throw
        Test-Path "HKEY_USERS:" | Should -Be $true

        { Get-Item "HKEY_USERS:" } | Should -Not -Throw

        $item = Get-Item "HKEY_USERS:"
        $item.PSProvider.Name | Should -Be "Registry"
    }
}
