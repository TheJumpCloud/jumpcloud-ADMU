Describe "Set-RegPermission Acceptance Tests" -Tag "Acceptance" {
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
    Context "Permission tests" {
        BeforeEach {
            $testDir = Join-Path $env:TEMP "SetRegPermissionTest"
            $sourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $sourceSID = $sourceUser.User.Value
            $targetSID = "S-1-5-32-544" # Administrators group SID for testing
            # Create test directory and files
            if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force }
            New-Item -ItemType Directory -Path $testDir | Out-Null
            New-Item -ItemType File -Path (Join-Path $testDir "testfile.txt") | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $testDir "subdir") | Out-Null
            New-Item -ItemType File -Path (Join-Path $testDir "subdir\subfile.txt") | Out-Null
        }

        AfterEach {
            if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force }
        }

        It "Should transfer ownership from SourceSID to TargetSID for all files and directories" {
            Set-RegPermission -SourceSID $sourceSID -TargetSID $targetSID -FilePath $testDir

            $items = Get-ChildItem -Path $testDir -Recurse -Force
            foreach ($item in $items) {
                $acl = Get-Acl $item.FullName
                $acl.Owner | Should -Be ((New-Object System.Security.Principal.SecurityIdentifier($targetSID)).Translate([System.Security.Principal.NTAccount]).Value)
            }
        }

        It "Should add TargetSID access rules matching SourceSID permissions" {
            # Give SourceSID FullControl on testfile.txt
            $filePath = Join-Path $testDir "testfile.txt"
            $acl = Get-Acl $filePath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sourceUser.Name,
                "FullControl",
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path $filePath -AclObject $acl

            Set-RegPermission -SourceSID $sourceSID -TargetSID $targetSID -FilePath $testDir

            $acl = Get-Acl $filePath
            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($targetSID)).Translate([System.Security.Principal.NTAccount]).Value
            $acl.Access | Where-Object { $_.IdentityReference -eq $targetAccount -and $_.FileSystemRights -eq "FullControl" } | Should -Not -BeNullOrEmpty
        }

        It "Should not change ownership if file is not owned by SourceSID" {
            $otherSID = "S-1-5-18" # Local System
            $otherAccount = (New-Object System.Security.Principal.SecurityIdentifier($otherSID)).Translate([System.Security.Principal.NTAccount]).Value
            $filePath = Join-Path $testDir "testfile.txt"
            $acl = Get-Acl $filePath
            $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($otherSID)))
            Set-Acl -Path $filePath -AclObject $acl

            Set-RegPermission -SourceSID $sourceSID -TargetSID $targetSID -FilePath $testDir

            $acl = Get-Acl $filePath
            $acl.Owner | Should -Be $otherAccount
        }
    }
}
