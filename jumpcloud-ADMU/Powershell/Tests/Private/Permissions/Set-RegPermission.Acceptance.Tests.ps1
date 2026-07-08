Describe "Set-RegPermission Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            $currentPath = Split-Path $currentPath -Parent
        }

        # Initialize help functions
        if ($helpFunctionDir) { . "$helpFunctionDir\$fileName" }

        # Setup baseline test users
        $testUsername = "regTest"
        Initialize-TestUser -Username $testUsername -password "Temp123!Temp123!" -ErrorAction SilentlyContinue
        $script:userSid = Test-UsernameOrSID -usernameOrSid $testUsername

        $script:sourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $script:sourceSID = $sourceUser.User.Value
    }

    Context "Input Validation and Error Handling" {
        It "Throws if the FilePath does not exist" {
            $fakePath = "C:\Temp\ThisPathDoesNotExist_$(New-Guid)"
            { Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $fakePath } | Should -Throw "Set-RegPermission path does not exist: $fakePath"
        }

        It "Throws if the FilePath is empty or whitespace" {
            { Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath "   " } | Should -Throw "Set-RegPermission requires a non-empty FilePath."
        }

        It "Skips and logs a warning for reparse points (Symlinks/Junctions) when -Recursive is specified" {
            $testDir = Join-Path $env:TEMP "RegPermReparseTest"
            $junctionDir = Join-Path $env:TEMP "RegPermJunctionTest"
            if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force }
            if (Test-Path $junctionDir) { Remove-Item $junctionDir -Force }

            New-Item -ItemType Directory -Path $testDir | Out-Null
            New-Item -ItemType Junction -Path $junctionDir -Target $testDir | Out-Null

            # Mock Write-ToLog so we can verify the warning was sent
            Mock Write-ToLog { }

            # Verify it no longer throws an exception
            {
                Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $junctionDir -Recursive
            } | Should -Not -Throw

            # Verify the warning was properly logged
            Assert-MockCalled Write-ToLog -Times 1 -ParameterFilter {
                $Level -eq 'Warning' -and $Message -match "Root path is a reparse point"
            }

            # Cleanup
            Remove-Item $junctionDir -Force
            Remove-Item $testDir -Force
        }
    }

    Context "Native C# Implementation (-Recursive)" {
        BeforeEach {
            $script:testDir = Join-Path $env:TEMP "SetRegPermissionNativeTest"
            if (Test-Path $script:testDir) { Remove-Item $script:testDir -Recurse -Force }

            # Build a nested directory structure
            New-Item -ItemType Directory -Path $script:testDir | Out-Null
            New-Item -ItemType File -Path (Join-Path $script:testDir "rootfile.txt") | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $script:testDir "subdir") | Out-Null
            New-Item -ItemType File -Path (Join-Path $script:testDir "subdir\subfile.txt") | Out-Null

            # Explicitly set current user as owner to baseline it
            $acl = Get-Acl $script:testDir
            $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($script:sourceSID)))
            Set-Acl -Path $script:testDir -AclObject $acl
        }

        AfterEach {
            if (Test-Path $script:testDir) { Remove-Item $script:testDir -Recurse -Force }
        }

        It "Should successfully compile NativeAcl and apply ownership recursively" {
            # Act
            Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $script:testDir -Recursive

            # Assert - Root Folder
            $rootAcl = Get-Acl $script:testDir
            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($script:userSid)).Translate([System.Security.Principal.NTAccount]).Value

            $rootAcl.Owner | Should -Be $targetAccount

            # Assert - Child Items
            $childItems = Get-ChildItem -Path $script:testDir -Recurse
            $childItems.Count | Should -BeGreaterThan 0

            foreach ($item in $childItems) {
                $childAcl = Get-Acl $item.FullName
                $childAcl.Owner | Should -Be $targetAccount

                # Verify FullControl was granted
                $hasFullControl = $childAcl.Access | Where-Object {
                    $_.IdentityReference -eq $targetAccount -and
                    $_.FileSystemRights -match "FullControl"
                }
                $hasFullControl | Should -Not -BeNullOrEmpty
            }
        }

        It "Should log a Warning with the file path and Win32 error code when a file is locked" {
            # Arrange - lock a nested file exclusively so the native tree operation cannot re-secure it
            $lockedPath = Join-Path $script:testDir "subdir\subfile.txt"
            $lockedHandle = [System.IO.File]::Open($lockedPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

            Mock Write-ToLog { }

            try {
                # Act - Verify it does not throw despite the locked file causing a per-item failure
                {
                    Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $script:testDir -Recursive
                } | Should -Not -Throw
            } finally {
                $lockedHandle.Close()
                $lockedHandle.Dispose()
            }

            # Assert - the specific locked file was logged individually with a Warning and a non-zero Win32 error
            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq 'Warning' -and $Message -match [regex]::Escape($lockedPath) -and $Message -match 'Win32 error \d+'
            }

            # Assert - the summary line reflects at least one error
            Assert-MockCalled Write-ToLog -ParameterFilter {
                $Level -eq 'Warning' -and $Message -match 'Native tree operation completed with' -and $Message -match '[1-9]\d* other error'
            }
        }
    }

    Context "icacls Fallback Implementation (Non-Recursive)" {
        BeforeEach {
            $script:testDir = Join-Path $env:TEMP "SetRegPermissionIcaclsTest"
            if (Test-Path $script:testDir) { Remove-Item $script:testDir -Recurse -Force }
            New-Item -ItemType Directory -Path $script:testDir | Out-Null
            New-Item -ItemType File -Path (Join-Path $script:testDir "testfile.txt") | Out-Null
        }

        AfterEach {
            if (Test-Path $script:testDir) { Remove-Item $script:testDir -Recurse -Force }
        }

        It "Should apply immediate-level ownership and permissions using icacls" {
            # Act - Note the omission of the -Recursive switch
            Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $script:testDir

            # Assert
            $acl = Get-Acl $script:testDir
            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($script:userSid)).Translate([System.Security.Principal.NTAccount]).Value

            $acl.Owner | Should -Be $targetAccount
            $acl.Access | Where-Object { $_.IdentityReference -eq $targetAccount -and $_.FileSystemRights -match "FullControl" } | Should -Not -BeNullOrEmpty
        }
    }

    Context "DAT and Log File Recovery Validation" {
        BeforeEach {
            $script:mockAppData = Join-Path $env:TEMP "MockAppData_DATTest_$([guid]::NewGuid())"
            if (Test-Path $script:mockAppData) { Remove-Item $script:mockAppData -Recurse -Force }
            New-Item -ItemType Directory -Path $script:mockAppData | Out-Null

            $script:filesToTest = @(
                "UsrClass.dat",
                "UsrClass.dat.LOG1",
                "UsrClass.dat.LOG2",
                "NTUSER.DAT",
                "NTUSER.DAT.LOG1",
                "NTUSER.DAT.LOG2"
            )

            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($script:userSid)).Translate([System.Security.Principal.NTAccount])

            # Create the files and explicitly strip permissions for the target user to simulate the issue
            foreach ($fileName in $script:filesToTest) {
                $filePath = Join-Path $script:mockAppData $fileName
                New-Item -ItemType File -Path $filePath | Out-Null

                $acl = Get-Acl $filePath
                $acl.SetAccessRuleProtection($true, $true) # Break inheritance, copy existing rules

                # Identify and remove any existing rules for the target user
                $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
                foreach ($rule in $rules) {
                    if ($rule.IdentityReference -eq $targetAccount) {
                        $acl.RemoveAccessRule($rule) | Out-Null
                    }
                }

                # Apply broken ACL
                Set-Acl -Path $filePath -AclObject $acl
            }
        }

        AfterEach {
            if (Test-Path $script:mockAppData) { Remove-Item $script:mockAppData -Recurse -Force }
        }

        It "Should successfully restore ownership and full permissions to DAT and LOG files" {
            # Act - Execute the tool against the directory recursively to verify it fixes the files
            Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $script:mockAppData -Recursive

            # Assert
            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($script:userSid)).Translate([System.Security.Principal.NTAccount]).Value

            foreach ($fileName in $script:filesToTest) {
                $filePath = Join-Path $script:mockAppData $fileName
                $acl = Get-Acl $filePath

                # Verify target SID now owns the file
                $acl.Owner | Should -Be $targetAccount

                # Verify target SID now has explicit FullControl
                $hasFullControl = $acl.Access | Where-Object {
                    $_.IdentityReference -eq $targetAccount -and
                    $_.FileSystemRights -match "FullControl"
                }

                $hasFullControl | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context "SID Translation Fallback Tests" {
        It "Falls back to SID string and throws if SID cannot be translated by System.Security.AccessControl" {
            $fakeSID = 'S-1-5-21-0000000000-0000000000-0000000000-1234'
            $targetSID = 'S-1-5-21-0000000000-0000000000-0000000000-5678'
            $testPath = Join-Path $env:TEMP "sidFallbackTest.txt"
            New-Item -Path $testPath -ItemType File -Force | Out-Null

            # Act & Assert
            # Attempting non-recursive AD ACL additions without -Recursive
            {
                Set-RegPermission -SourceSID $fakeSID -TargetSID $targetSID -FilePath $testPath -ErrorAction Stop
            } | Should -Throw 'Exception calling "AddAccessRule" with "1" argument(s): "Some or all identity references could not be translated."'

            # Cleanup
            Remove-Item $testPath -Force
        }
    }
}