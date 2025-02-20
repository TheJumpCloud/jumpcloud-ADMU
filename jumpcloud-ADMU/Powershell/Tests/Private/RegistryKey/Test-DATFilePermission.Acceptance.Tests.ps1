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
        . "$helpFunctionDir\initialize-TestUser.ps1"
    }

    Context 'Validates that the  Registry Hive Permissions are correct, given a username' {
        It 'Should return true when a users ntfs permissions are correct' {
            $datUserTrue = "ADMU_dat_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUserTrue -Password $Password

            # Test NTFS NTUser dat permissions
            $NTUser, $permissionHash = Test-DATFilePermission -Path "C:\Users\$datUserTrue\NTUSER.DAT" -username $datUserTrue -type 'ntfs'
            # Test UsrClass dat permissions
            $UsrClass, $permissionHash = Test-DATFilePermission -Path "C:\Users\$datUserTrue\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $datUserTrue -type 'ntfs'
            # Validate NTFS Permissions
            $NTUser | Should -Be $true
            $UsrClass | Should -Be $true
            # load file into memory + test registry permissions
            if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS") {
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }
            REG LOAD HKU\$($datUserTrue) "C:\Users\$datUserTrue\NTUSER.DAT" *>&1
            REG LOAD HKU\$($datUserTrue)_classes "C:\Users\$datUserTrue\AppData\Local\Microsoft\Windows\UsrClass.dat" *>&1
            # Test NTUSER dat permissions
            $NTUser, $permissionHash = Test-DATFilePermission -Path "HKEY_USERS:\$($datUserTrue)" -username $datUserTrue -type 'registry'
            # Test UsrClass dat permissions
            $UsrClass, $permissionHashClasses = Test-DATFilePermission -Path "HKEY_USERS:\$($datUserTrue)_classes" -username $datUserTrue -type 'registry'
            # Validate registry Permissions
            $NTUser | Should -Be $true
            $UsrClass | Should -Be $true

            # unload registry files
            # REG UNLOAD HKU\$($datUserTrue) *>&1
            # REG UNLOAD HKU\$($datUserTrue)_classes *>&1
        }
        It 'Should return false when a users ntfs permissions are correct' {
            $datUserFalse = "ADMU_dat_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            Initialize-TestUser -UserName $datUserFalse -Password $Password
            $filePaths = @("C:\Users\$datUserFalse\AppData\Local\Microsoft\Windows\UsrClass.dat", "C:\Users\$datUserFalse\NTUSER.DAT")
            $requiredAccounts = @("SYSTEM", "$datUserFalse")
            # NTFS Validations:
            foreach ($FilePath in $filePaths) {
                # Get current access control list:
                $FileACL = (Get-Item $FilePath -Force).GetAccessControl('Access')

                # Remove inheritance but preserve existing entries
                $FileACL.SetAccessRuleProtection($true, $true)
                Set-Acl $FilePath -AclObject $FileACL

                # Retrieve new explicit set of permissions
                $FileACL = Get-Acl $FilePath

                foreach ($requiredAccount in $requiredAccounts) {
                    # Retrieve one of the required rules
                    Write-Host "removing: $($requiredAccount) Access"
                    $ruleToRemove = $FileACL.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]) | Where-Object { $_.IdentityReference -match $requiredAccount }

                    # Remove it - or modify it and use SetAccessRule() instead
                    $FileACL.RemoveAccessRule($ruleToRemove)

                    # Set ACL on file again
                    Set-Acl $FilePath -AclObject $FileACL

                    # Test NTUser dat permissions
                    $NTUser, $permissionHash = Test-DATFilePermission -Path $FilePath -username $datUserFalse -type 'ntfs'
                    $NTUser | Should -Be $false

                    # Retrieve new explicit set of permissions
                    $FileACL = Get-Acl $FilePath

                    # Add the rule again
                    $FileACL.SetAccessRule($ruleToRemove)
                    # Set ACL on file again
                    Set-Acl $FilePath -AclObject $FileACL
                    $NTUser, $permissionHashClasses = Test-DATFilePermission -Path $FilePath -username $datUserFalse -type 'ntfs'
                    # Test UsrClass dat permissions
                    $NTUser | Should -Be $true
                }
            }
            # Registry Validations:
            # load file into memory + test registry permissions
            if ((Get-psdrive | select-object name) -notmatch "HKEY_USERS") {
                New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS")
            }
            foreach ($FilePath in $filePaths) {
                if ($filePath -match 'usrclass') {
                    REG LOAD "HKU\tempPath_classes" "$FilePath" *>&1
                    $REGFilePath = "HKEY_USERS:\tempPath_classes"
                } else {
                    REG LOAD "HKU\tempPath" "$FilePath" *>&1
                    $REGFilePath = "HKEY_USERS:\tempPath"
                }
                # Get current access control list:
                $FileACL = (Get-Item $REGFilePath -Force).GetAccessControl('Access')

                # Remove inheritance but preserve existing entries
                $FileACL.SetAccessRuleProtection($true, $true)
                Set-Acl $REGFilePath -AclObject $FileACL

                # Retrieve new explicit set of permissions
                $FileACL = Get-Acl $REGFilePath
                foreach ($requiredAccount in $requiredAccounts) {
                    # Retrieve one of the required rules
                    Write-Host "removing: $($requiredAccount) Access"
                    $ruleToRemove = $FileACL.GetAccessRules($true, $true, [System.Security.Principal.NTAccount]) | Where-Object { $_.IdentityReference -match $requiredAccount }

                    # Remove it - or modify it and use SetAccessRule() instead
                    $FileACL.RemoveAccessRule($ruleToRemove)

                    # Set ACL on file again
                    Set-Acl $REGFilePath -AclObject $FileACL

                    # Test registry dat permissions
                    $NTUser, $permissionHash = Test-DATFilePermission -Path $REGFilePath -username $datUserFalse -type 'registry'
                    $NTUser | Should -Be $false

                    # Retrieve new explicit set of permissions
                    $FileACL = Get-Acl $REGFilePath

                    # Add the rule again
                    $FileACL.SetAccessRule($ruleToRemove)
                    # Set ACL on file again
                    Set-Acl $REGFilePath -AclObject $FileACL
                    $NTUser, $permissionHashClasses = Test-DATFilePermission -Path $REGFilePath -username $datUserFalse -type 'registry'
                    # Test UsrClass dat permissions
                    $NTUser | Should -Be $true
                }
            }
        }
    }

    # It "Should Test NTFS DAT File Permission" {

    #     # Test NTFS NTUser dat permissions
    #     $NTUser, $permissionHash = Test-DATFilePermission -Path "C:\Users\$($env:USERNAME)\NTUSER.DAT" -username $($env:USERNAME) -type 'ntfs'

    #     # Validate NTFS Permissions
    #     $NTUser | Should -Be $true
    #     $permissionHash | Should -Not -BeNullOrEmpty
    # }

    # It "Should Test UsrClass DAT File Permission" {
    #     # Test NTFS UsrClass dat permissions
    #     $UsrClass, $permissionHash = Test-DATFilePermission -Path "C:\Users\$($env:USERNAME)\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $($env:USERNAME) -type 'ntfs'

    #     # Validate NTFS Permissions
    #     $UsrClass | Should -Be $true
    #     $permissionHash | Should -Not -BeNullOrEmpty

    # }

    # Add more acceptance tests as needed
}
