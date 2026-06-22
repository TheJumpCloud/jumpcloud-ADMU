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

        It 'Should return $true when SYSTEM, Administrators, and the target User have Allow access' {
            # Setup User
            $datUser = "ADMU_tstprnt_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUser -Password $Password

            # Translate Username to SID for the parameter
            $ntAccount = New-Object System.Security.Principal.NTAccount($datUser)
            $userSID = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value

            # Target the newly created user profile directory
            $dirPath = "C:\Users\$datUser"

            $isValid = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $isValid | Should -Be $true
        }

        It 'Should return $false when the target User is missing Allow access' {
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

            $isValid = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $isValid | Should -Be $false
        }

        It 'Should return $false when SYSTEM or Administrators are missing Allow access' {
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

            $isValid = Test-DATParentPermission -DirectoryPath $dirPath -UserSID $userSID
            $isValid | Should -Be $false
        }

        It 'Should return $false if the directory does not exist' {
            $fakeUserSID = "S-1-5-21-1234567890-1234567890-1234567890-1001"
            $fakeDirPath = "C:\Fake\Path\That\Definitely\Does\Not\Exist"

            # The function uses SilentlyContinue, so it should return false rather than throwing
            $isValid = Test-DATParentPermission -DirectoryPath $fakeDirPath -UserSID $fakeUserSID
            $isValid | Should -Be $false
        }
    }
}