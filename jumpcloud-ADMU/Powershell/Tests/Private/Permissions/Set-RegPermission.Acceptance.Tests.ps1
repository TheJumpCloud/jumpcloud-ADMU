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

        It "Refuses to natively follow reparse points (Symlinks/Junctions) when -Recursive is specified" {
            $testDir = Join-Path $env:TEMP "RegPermReparseTest"
            $junctionDir = Join-Path $env:TEMP "RegPermJunctionTest"
            if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force }
            if (Test-Path $junctionDir) { Remove-Item $junctionDir -Force }

            New-Item -ItemType Directory -Path $testDir | Out-Null
            New-Item -ItemType Junction -Path $junctionDir -Target $testDir | Out-Null

            {
                Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $junctionDir -Recursive
            } | Should -Throw "root path is a reparse point (symlink or junction); refusing to follow natively."

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

        It "Should invoke the progress heartbeat scriptblock during icacls execution" {
            # Arrange - Generate enough files to ensure icacls takes at least 1 full second
            $largeDir = Join-Path $script:testDir "LargeDir"
            New-Item -ItemType Directory -Path $largeDir | Out-Null
            1..200 | ForEach-Object {
                New-Item -ItemType File -Path (Join-Path $largeDir "file_$_.txt") | Out-Null
            }

            $script:heartbeatTriggered = $false
            $onHeartbeat = { $script:heartbeatTriggered = $true }

            # Clear the global error array to prevent leftover errors from failing this test
            $error.Clear()

            # Act
            Set-RegPermission -SourceSID $script:sourceSID -TargetSID $script:userSid -FilePath $largeDir -ProgressHeartbeatIntervalSeconds 1 -OnProgressHeartbeat $onHeartbeat

            # Assert
            $error.Count | Should -Be 0
            $script:IcaclsExitCode | Should -Be 0

            # Verify the permissions actually applied to ensure the run was successful
            $acl = Get-Acl $largeDir
            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($script:userSid)).Translate([System.Security.Principal.NTAccount]).Value
            $acl.Owner | Should -Be $targetAccount
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