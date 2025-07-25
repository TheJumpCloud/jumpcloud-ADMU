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
        $testUsername = "regTest"
        Initialize-TestUser -Username $testUsername -password "Temp123!Temp123!"
        $userSid = Test-UsernameOrSID -usernameOrSid $testUsername

    }
    Context "Permission tests" {
        BeforeEach {
            $testDir = Join-Path $HOME "SetRegPermissionTest"
            $sourceUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $sourceSID = $sourceUser.User.Value

            $targetSID = $userSid
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

        It "Should transfer ownership from SourceSID to TargetSID for all files and directories when the SourceSID is the owner of the files and directories" {
            # first set the ownership to SourceID
            $items = Get-ChildItem -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue
            # Create SecurityIdentifier objects
            $SourceSIDObj = New-Object System.Security.Principal.SecurityIdentifier($SourceSID)
            $TargetSIDObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)

            # Get NTAccount names for logging and ACLs
            $SourceAccount = $SourceSIDObj.Translate([System.Security.Principal.NTAccount]).Value
            $TargetAccount = $TargetSIDObj.Translate([System.Security.Principal.NTAccount]).Value
            foreach ($item in $items) {

                $acl = Get-Acl -Path $item.FullName
                # Change owner if SourceSID is current owner
                if (($acl.Owner -ne $SourceAccount)) {
                    $acl.SetOwner($SourceSIDObj)
                    Set-Acl -Path $item.FullName -AclObject $acl

                }
            }
            # then attempt to update the ownership
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
                [System.Security.AccessControl.InheritanceFlags]::None,
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
