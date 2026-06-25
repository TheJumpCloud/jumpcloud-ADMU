Describe "Test-DATParentPermission Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        $currentPath = $PSScriptRoot
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
        . "$helpFunctionDir\$FileName"
        . "$helpFunctionDir\initialize-TestUser.ps1"
    }

    Context 'Evaluates directory permissions for required SIDs' {

        It 'Should return IsValid $true when SYSTEM, Administrators, and the target User have Allow access' {
            # Setup User
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            # Translate Username to SID for the parameter
            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

            # Target the newly created user profile directory
            $dirPath = "C:\Users\$datUser"

            $result = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $result.IsValid | Should -Be $true
            $result.MissingIdentities | Should -BeNullOrEmpty
            $result.InsufficientRights | Should -BeNullOrEmpty
        }

        It 'Should report the target User in MissingIdentities when Allow access is missing' {
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $dirPath = "C:\Users\$datUser"

            # Break the ACL: Disable inheritance and set protection
            $dirACL = Get-Acl $dirPath
            $dirACL.SetAccessRuleProtection($true, $true)
            Set-Acl $dirPath -AclObject $dirACL

            # Remove the test user's access rules
            $dirACL = Get-Acl $dirPath
            $rulesToRemove = $dirACL.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]) | Where-Object { $_.IdentityReference -match $datUser }
            if ($rulesToRemove) {
                foreach ($rule in $rulesToRemove) {
                    $dirACL.RemoveAccessRule($rule) | Out-Null
                }
                Set-Acl $dirPath -AclObject $dirACL
            }

            $result = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $result.IsValid | Should -Be $false
            $expectedIdentity = (New-Object System.Security.Principal.SecurityIdentifier($userSID)).Translate([System.Security.Principal.NTAccount]).Value
            $result.MissingIdentities | Should -Contain $expectedIdentity
        }

        It 'Should report NT AUTHORITY\SYSTEM in MissingIdentities when SYSTEM Allow access is missing' {
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $dirPath = "C:\Users\$datUser"

            # Break the ACL: Disable inheritance and set protection
            $dirACL = Get-Acl $dirPath
            $dirACL.SetAccessRuleProtection($true, $true)
            Set-Acl $dirPath -AclObject $dirACL

            # Remove the NT AUTHORITY\SYSTEM access rule (S-1-5-18)
            $dirACL = Get-Acl $dirPath
            $rulesToRemove = $dirACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-5-18' }
            if ($rulesToRemove) {
                foreach ($rule in $rulesToRemove) {
                    $dirACL.RemoveAccessRule($rule) | Out-Null
                }
                Set-Acl $dirPath -AclObject $dirACL
            }

            $result = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $result.IsValid | Should -Be $false
            $result.MissingIdentities | Should -Contain 'NT AUTHORITY\SYSTEM'
        }

        It 'Should report insufficient filesystem rights when Allow ACE lacks directory traversal rights' {
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $dirPath = "C:\Users\$datUser"

            $dirACL = Get-Acl $dirPath
            $dirACL.SetAccessRuleProtection($true, $false)
            $dirACL.Access | ForEach-Object { $dirACL.RemoveAccessRule($_) | Out-Null }

            $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $userSidObj = New-Object System.Security.Principal.SecurityIdentifier($userSID)

            foreach ($sid in @($systemSid, $adminSid)) {
                $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $sid,
                            [System.Security.AccessControl.FileSystemRights]::FullControl,
                            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )))
            }

            # Grant the user Write only (insufficient for directory traversal)
            $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $userSidObj,
                        [System.Security.AccessControl.FileSystemRights]::Write,
                        [System.Security.AccessControl.InheritanceFlags]::None,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        [System.Security.AccessControl.AccessControlType]::Allow
                    )))
            Set-Acl $dirPath -AclObject $dirACL

            $result = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $result.IsValid | Should -Be $false
            $expectedIdentity = (New-Object System.Security.Principal.SecurityIdentifier($userSID)).Translate([System.Security.Principal.NTAccount]).Value
            ($result.InsufficientRights | Where-Object { $_.Identity -eq $expectedIdentity }) | Should -Not -BeNullOrEmpty
            ($result.InsufficientRights | Where-Object { $_.Identity -eq $expectedIdentity }).MissingRights | Should -Not -BeNullOrEmpty
        }

        It 'Should report the target User in MissingIdentities when only InheritOnly Allow access exists' {
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $dirPath = "C:\Users\$datUser"

            $dirACL = Get-Acl $dirPath
            $dirACL.SetAccessRuleProtection($true, $false)
            $dirACL.Access | ForEach-Object { $dirACL.RemoveAccessRule($_) | Out-Null }

            $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $userSidObj = New-Object System.Security.Principal.SecurityIdentifier($userSID)

            foreach ($sid in @($systemSid, $adminSid)) {
                $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $sid,
                            [System.Security.AccessControl.FileSystemRights]::FullControl,
                            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )))
            }

            $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $userSidObj,
                        [System.Security.AccessControl.FileSystemRights]::FullControl,
                        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                        [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                        [System.Security.AccessControl.AccessControlType]::Allow
                    )))
            Set-Acl $dirPath -AclObject $dirACL

            $result = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $result.IsValid | Should -Be $false
            $expectedIdentity = (New-Object System.Security.Principal.SecurityIdentifier($userSID)).Translate([System.Security.Principal.NTAccount]).Value
            $result.MissingIdentities | Should -Contain $expectedIdentity
        }

        It 'Should report insufficient rights when explicit Deny blocks applicable Allow access' {
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $dirPath = "C:\Users\$datUser"

            $dirACL = Get-Acl $dirPath
            $dirACL.SetAccessRuleProtection($true, $false)
            $dirACL.Access | ForEach-Object { $dirACL.RemoveAccessRule($_) | Out-Null }

            $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
            $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $userSidObj = New-Object System.Security.Principal.SecurityIdentifier($userSID)

            foreach ($sid in @($systemSid, $adminSid)) {
                $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $sid,
                            [System.Security.AccessControl.FileSystemRights]::FullControl,
                            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )))
            }

            $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $userSidObj,
                        [System.Security.AccessControl.FileSystemRights]::FullControl,
                        [System.Security.AccessControl.InheritanceFlags]::None,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        [System.Security.AccessControl.AccessControlType]::Allow
                    )))
            $dirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $userSidObj,
                        [System.Security.AccessControl.FileSystemRights]::FullControl,
                        [System.Security.AccessControl.InheritanceFlags]::None,
                        [System.Security.AccessControl.PropagationFlags]::None,
                        [System.Security.AccessControl.AccessControlType]::Deny
                    )))
            Set-Acl $dirPath -AclObject $dirACL

            $result = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $result.IsValid | Should -Be $false
            $expectedIdentity = (New-Object System.Security.Principal.SecurityIdentifier($userSID)).Translate([System.Security.Principal.NTAccount]).Value
            ($result.InsufficientRights | Where-Object { $_.Identity -eq $expectedIdentity }) | Should -Not -BeNullOrEmpty
            ($result.InsufficientRights | Where-Object { $_.Identity -eq $expectedIdentity }).MissingRights | Should -Not -BeNullOrEmpty
        }

        It 'Should return IsValid $false if the directory does not exist' {
            $fakeUserSID = "S-1-5-21-1234567890-1234567890-1234567890-1001"
            $fakeDirPath = "C:\Fake\Path\That\Definitely\Does\Not\Exist"

            $result = Test-DATParentPermission -DirectoryPath $fakeDirPath -UserSID $fakeUserSID
            $result.IsValid | Should -Be $false
            $result.MissingIdentities | Should -Contain 'Directory not accessible or does not exist'
        }
    }
}
