BeforeAll {
    Write-Host "Script Location: $PSScriptRoot"
    Write-Host "Dot-Sourcing Start-Migration Script"
    . $PSScriptRoot\..\Start-Migration.ps1
    Write-Host "Dot-Sourcing Test Functions"
    . $PSScriptRoot\SetupAgent.ps1
    Write-Host "Running Connect-JCOnline"
    Connect-JCOnline -JumpCloudApiKey $env:JCApiKey -JumpCloudOrgId $env:JCOrgId -Force
}
Describe 'Functions' {
    Context 'Show-Result Function' -Skip {
        # This is a GUI test, check manually before release
    }

    Context 'Test-RegistryValueMatch Function' {
        # Test that the Test-RegistryValueMatch function returns valid results from the registry
        It 'Value matches' {
            Test-RegistryValueMatch -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Value 'Public' -stringmatch 'Public' | Should -Be $true
        }

        It 'Value does not match' {
            Test-RegistryValueMatch -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Value 'Public' -stringmatch 'Private' | Should -Be $false
        }
    }
    Context 'Test-JumpCloudUsername Function' {
        It 'Valid Username Returns True' {
            # Get the first user
            $user = Get-JcSdkUser | Select-Object -First 1
            # Test username w/o modification
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:JCApiKey -Username $user.Username
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
            # toUpper
            $upper = ($user.Username).ToUpper()
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:JCApiKey -Username $upper
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
            # to lower
            $lower = ($user.Username).ToLower()
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:JCApiKey -Username $lower
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
        }
        It 'Invalid Username Returns False' {
            # Get the first user
            $user = Get-JcSdkUser | Select-Object -First 1
            # Append random string to username
            $newUsername = $user.Username + "jdksf45kjfds"
            # Test function
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:JCApiKey -Username $newUsername
            $testResult | Should -Be $false
            $userID | Should -Be $null
        }
    }

    Context 'Set-JCUserToSystemAssociation Function' {
        # Set-JCUserToSystemAssociation should take USERID as input validated with Test-JumpCloudUsername
        BeforeAll {
            $OrgID, $OrgName = Get-mtpOrganization -apiKey $env:JCApiKey

            $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        }
        It 'Bind As non-Administrator' {
            # Get ORG ID for
            # Generate New User
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # If User Exists, remove from the org
            $users = Get-JCSDKUser
            if ("$($user.JCUsername)" -in $users.Username) {
                $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                Remove-JcSdkUser -Id $existing.Id
            }
            $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
            # Begin Test
            Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
            $bind = Set-JCUserToSystemAssociation -JcApiKey $env:JCApiKey -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
            $bind | Should -Be $true
            $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
            $association | Should -not -BeNullOrEmpty
            $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $null
            # Clean Up
            Remove-JcSdkUser -Id $GeneratedUser.Id
        }
        It 'Bind As non-Administrator' {
            # Get ORG ID for
            # Generate New User
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # If User Exists, remove from the org
            $users = Get-JCSDKUser
            if ("$($user.JCUsername)" -in $users.Username) {
                $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                Remove-JcSdkUser -Id $existing.Id
            }
            $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
            # Begin Test
            Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
            $bind = Set-JCUserToSystemAssociation -JcApiKey $env:JCApiKey -JcOrgId $OrgID -JcUserID $GeneratedUser.Id -BindAsAdmin $true
            $bind | Should -Be $true
            # ((Get-JCAssociation -Type:user -Id:($($GeneratedUser.Id))).id).count | Should -Be '1'
            $association = Get-JcSdkSystemAssociation -systemid $systemKey -Targets user | Where-Object { $_.ToId -eq $($GeneratedUser.Id) }
            $association | Should -not -BeNullOrEmpty
            $association.Attributes.AdditionalProperties.sudo.enabled | Should -Be $true
            # Clean Up
            Remove-JcSdkUser -Id $GeneratedUser.Id
        }

        It 'APIKey not valid' {
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
            $bind = Set-JCUserToSystemAssociation -JcApiKey '1234122341234234123412341234123412341234' -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
            $bind | Should -Be $false
        }

        It 'Agent not installed' -skip {
            #TODO: Is this test necessary, it breaks the migration tests
            if ((Test-Path -Path "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf") -eq $True) {
                Remove-Item "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
            }
            { Set-JCUserToSystemAssociation -JcApiKey $env:JCApiKey -JcUserID $GeneratedUser.Id -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'DenyInteractiveLogonRight Function' -Skip {
        #SeDenyInteractiveLogonRight not present in circleci instance
        It 'User exists on system' {
            # $objUser = New-Object System.Security.Principal.NTAccount("circleci")
            # $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
            # DenyInteractiveLogonRight -SID $strSID.Value
            # $secpolFile = "C:\Windows\temp\ur_orig.inf"
            # if (Test-Path $secpolFile)
            # {
            #     Remove-Item $secpolFile -Force
            # }
            # secedit /export /areas USER_RIGHTS /cfg C:\Windows\temp\ur_orig.inf
            # $secpol = (Get-Content $secpolFile)
            # $regvaluestring = $secpol | Where-Object { $_ -like "*SeDenyInteractiveLogonRight*" }
            # $regvaluestring.Contains($strSID.Value) | Should -Be $true
        }

    }

    Context 'Register-NativeMethod Function' -Skip {
        # Register a C# Method to PWSH context we effectively test this with Migration tests
    }

    Context 'Add-NativeMethod Function' -Skip {
        # Add a C# Method to PWSH context we effectively test this with Migration tests
    }

    Context 'New-LocalUserProfile Function' {
        It 'User created and exists on system' {
            $newUserPassword = ConvertTo-SecureString -String 'Temp123!' -AsPlainText -Force
            New-localUser -Name 'testjc' -password $newUserPassword -Description "Created By JumpCloud ADMU tests"
            New-LocalUserProfile -username:('testjc')
            Test-Path -Path 'C:\Users\testjc' | Should -Be $true
        }

        It 'User does not exist on system and throws exception' {
            { New-LocalUserProfile -username:('userdoesntexist') -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Remove-LocalUserProfile Function' {
        It 'Add and remove,user should not exist on system' {
            $newUserPassword = ConvertTo-SecureString -String 'Temp123!' -AsPlainText -Force
            New-localUser -Name 'testremovejc2' -password $newUserPassword -Description "Created By JumpCloud ADMU tests"
            New-LocalUserProfile -username:('testremovejc2')
            # This test should be fail because the description is not correct
            { Remove-LocalUserProfile -username:('testremovejc2') } | Should -Throw
            Test-Path -Path 'C:\Users\testremovejc2' | Should -Be $true
            New-localUser -Name 'testremovejc3' -password $newUserPassword -Description "Created By JumpCloud ADMU"
            New-LocalUserProfile -username:('testremovejc3')
            { Remove-LocalUserProfile -username:('testremovejc3') } | Should -Not -Throw
            # This test should pass fail because the description set correctly
            Test-Path -Path 'C:\Users\testremovejc3' | Should -Be $false
        }

        It 'User does not exist on system and throws exception' {
            { Remove-LocalUserProfile -username:('randomusernamethatdoesntexist') -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Set-ValueToKey Function' {
        # Test that we can write to the registry when providing a key and value
        It 'Value is set on existing key' {
            Set-ValueToKey -registryRoot LocalMachine -keyPath 'SYSTEM\Software' -name '1' -value '1' -regValueKind DWord
            Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\Software\' -Name '1' | Should -Be '1'
        }
    }

    Context 'New-RegKey Function' {
        # Test that we can create new keys
        It 'Key is created' {
            New-RegKey -keyPath 'SYSTEM\1' -registryRoot LocalMachine
            test-path 'HKLM:\SYSTEM\1' | Should -Be $true
        }
    }

    Context 'Get-SID Function' {
        It 'Profile exists and sid returned' {
            # SID of circleCI user should match SID regex pattern
            Get-SID -User:'circleci' -cnotmatch "^S-\d-\d+-(\d+-){1,14}\d+$" | Should -Be $true
        }
    }

    Context 'Set-UserRegistryLoadState Function' -Skip {
        # Unload and load user registry - we are testing this in Migration tests
        It 'Load ' {
            # $circlecisid = (Get-SID -User:'circleci')
            # Set-UserRegistryLoadState -op Load -ProfilePath 'C:\Users\circleci\' -UserSid $circlecisid
            # $path = 'HKU:\' $circlecisid_'_a
            # Test-Path -Path 'HKU:\$($circlecisid)'
        }

        It 'Unload' {

        }
    }

    Context 'Test-UserRegistryLoadState Function' -skip {
        # Tested in Migration Tests
    }

    Context 'Backup-RegistryHive Function' -skip {
        # Tested in Migration Tests
    }

    Context 'Get-ProfileImagePath Function' -skip {
        # Tested in Migration Tests
    }

    Context 'Get-WindowsDrive Function' {
        It 'Get-WindowsDrive - C' {
            Get-WindowsDrive | Should -Be "C:"
        }
    }

    Context 'Write-ToLog Function' {

        It 'Write-ToLog - ' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-ToLog -Message:('Log is created - test.') -Level:('Info')
            $log = 'C:\windows\Temp\jcAdmu.log'
            $log | Should -exist
        }

        It 'Write-ToLog - Log is created' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-ToLog -Message:('Log is created - test.') -Level:('Info')
            $log = 'C:\windows\Temp\jcAdmu.log'
            $log | Should -exist
        }

        It 'Write-ToLog - ERROR: Log entry exists' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            # Write-ToLog -Message:('Test Error Log Entry.') -Level:('Error') -ErrorAction
            #$Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            #$Log.Contains('ERROR: Test Error Log Entry.') | Should -Be $true
            #    if ($error.Count -eq 1) {
            #    $error.Clear()
            #    }
        }

        It 'Write-ToLog - WARNING: Log entry exists' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-ToLog -Message:('Test Warning Log Entry.') -Level:('Warn')
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('WARNING: Test Warning Log Entry.') | Should -Be $true
        }

        It 'Write-ToLog - INFO: Log entry exists' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Write-ToLog -Message:('Test Info Log Entry.') -Level:('Info')
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('INFO: Test Info Log Entry.') | Should -Be $true
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
    }

    Context 'Remove-ItemIfExist Function' {

        It 'Remove-ItemIfExist - Does Exist c:\windows\temp\test\' {
            if (Test-Path 'c:\windows\Temp\test\') {
                Remove-Item 'c:\windows\Temp\test' -Recurse -Force
            }
            New-Item -ItemType directory -path 'c:\windows\Temp\test\'
            New-Item 'c:\windows\Temp\test\test.txt'
            Remove-ItemIfExist -Path 'c:\windows\Temp\test\' -Recurse
            Test-Path 'c:\windows\Temp\test\' | Should -Be $false
        }

        It 'Remove-ItemIfExist - Fails c:\windows\temp\test\' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Mock Remove-ItemIfExist { Write-ToLog -Message ('Removal Of Temp Files & Folders Failed') -Level Warn }
            Remove-ItemIfExist -Path 'c:\windows\Temp\test\'
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('Removal Of Temp Files & Folders Failed') | Should -Be $true
        }
    }

    Context 'Test-ProgramInstalled Function' {

        It 'Test-ProgramInstalled x64 - PowerShell 7-x64' {
            test-programinstalled -programName 'PowerShell 7-x64' | Should -Be $true
        }

        It 'Test-ProgramInstalled x32 - WinAppDeploy' {
            Test-ProgramInstalled -programName 'WinAppDeploy' | Should -Be $true
        }

        It 'Test-ProgramInstalled - Program Name Does Not Exist' {
            Test-ProgramInstalled -programName 'Google Chrome1' | Should -Be $false
        }
    }

    Context 'Uninstall-Program Function' {

        It 'Uninstall - aws command line interface' -Skip {
            #TODO: This test actually be install something new, and uninstall should work
            uninstall-program -programname 'AWS Command Line Interface'
            start-sleep -Seconds 5
            Test-ProgramInstalled -programName 'AWS Command Line Interface' | Should -Be $false
        }
    }

    Context 'Start-NewProcess Function' {

        It 'Start-NewProcess - Notepad' {
            Start-NewProcess -pfile:('c:\windows\system32\notepad.exe') -Timeout 1000
            (Get-Process -Name 'notepad') -ne $null | Should -Be $true
            Stop-Process -Name "notepad"
        }

        It 'Start-NewProcess & end after 2s timeout - Notepad ' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
            Start-NewProcess -pfile:('c:\windows\system32\notepad.exe') -Timeout 1000
            Start-Sleep -s 2
            Stop-Process -Name "notepad"
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('Windows ADK Setup did not complete after 5mins') | Should -Be $true
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
    }

    Context 'Test-IsNotEmpty Function' {

        It 'Test-IsNotEmpty - $null' {
            Test-IsNotEmpty -field $null | Should -Be $true
        }

        It 'Test-IsNotEmpty - empty' {
            Test-IsNotEmpty -field '' | Should -Be $true
        }

        It 'Test-IsNotEmpty - test string' {
            Test-IsNotEmpty -field 'test' | Should -Be $false
        }
    }

    Context 'Test-CharLen -len 40 -testString Function' {

        It 'Test-CharLen -len 40 -testString - $null' {
            Test-CharLen -len 40 -testString $null | Should -Be $false
        }

        It 'Test-CharLen -len 40 -testString - 39 Chars' {
            Test-CharLen -len 40 -testString '111111111111111111111111111111111111111' | Should -Be $false
        }

        It 'Test-CharLen -len 40 -testString - 40 Chars' {
            Test-CharLen -len 40 -testString '1111111111111111111111111111111111111111' | Should -Be $true
        }
    }

    Context 'Test-HasNoSpace Function' {

        It 'Test-HasNoSpace - $null' {
            Test-HasNoSpace -field $null | Should -Be $true
        }

        It 'Test-HasNoSpace - no spaces' {
            Test-HasNoSpace -field 'testwithnospaces' | Should -Be $true
        }

        It 'Test-HasNoSpace - spaces' {
            Test-HasNoSpace -field 'test with spaces' | Should -Be $false
        }
    }

    Context 'Add-LocalUser Function' {

        It 'Add-LocalUser - testuser to Users ' {
            net user testuser /delete | Out-Null
            net user testuser Temp123! /add
            Remove-LocalGroupMember -Group "Users" -Member "testuser"
            Add-LocalGroupMember -SID S-1-5-32-545 -Member 'testuser'
            (([ADSI]"WinNT://./Users").psbase.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('AdsPath') } ) -match 'testuser' | Should -Be $true
        }
    }

    Context 'Test-Localusername Function' {

        It 'Test-Localusername - exists' {

            Test-Localusername -field 'circleci' | Should -Be $true
        }

        It 'Test-Localusername - does not exist' {

            Test-Localusername -field 'blazarz' | Should -Be $false
        }
    }

    Context 'Test-Domainusername Function' {
        # Requires domainjoined system
        It 'Test-Domainusername - exists' -skip {

            Test-Domainusername -field 'bob.lazar' | Should -Be $true
        }

        It 'Test-Domainusername - does not exist' {

            Test-Domainusername -field 'bob.lazarz' | Should -Be $false
        }
    }

    Context 'Install-JumpCloudAgent Function' {
        #Already installed on circleci
        It 'Install-JumpCloudAgent - Verify Download JCAgent prereq Visual C++ 2013 x64' -skip {
            Test-path 'C:\Windows\Temp\JCADMU\vc_redist.x64.exe' | Should -Be $true
        }
        #Already installed on circleci
        It 'Install-JumpCloudAgent - Verify Download JCAgent prereq Visual C++ 2013 x86' -skip {
            Test-path 'C:\Windows\Temp\JCADMU\vc_redist.x86.exe' | Should -Be $true
        }

        It 'Install-JumpCloudAgent - Verify Download JCAgent' {
            Test-path 'C:\Windows\Temp\JCADMU\jcagent-msi-signed.msi' | Should -Be $true
        }

        It 'Install-JumpCloudAgent - Verify Install JCAgent prereq Visual C++ 2013 x64' {
            (Test-ProgramInstalled("Microsoft Visual C\+\+ 2013 x64")) | Should -Be $true
        }

        It 'Install-JumpCloudAgent - Verify Install JCAgent prereq Visual C++ 2013 x86' {
            (Test-ProgramInstalled("Microsoft Visual C\+\+ 2013 x86")) | Should -Be $true
        }

        It 'Install-JumpCloudAgent - Verify Install JCAgent' {
            (Test-ProgramInstalled("JumpCloud")) | Should -Be $true
        }
    }

    Context 'Get-NetBiosName Function' {
        # Requires domainjoined system
        It 'Get-NetBiosName - JCADB2' -Skip {
            Get-NetBiosName | Should -Be 'JCADB2'
        }
    }

    Context 'Convert-SID Function' {
        BeforeAll {
            $newUserPassword = ConvertTo-SecureString -String 'Temp123!' -AsPlainText -Force
            New-localUser -Name 'sidTest' -password $newUserPassword -Description "Created By JumpCloud ADMU tests"
            New-LocalUserProfile -username:('sidTest')
        }
        It 'Convert-SID - circleci SID' {
            $circlecisid = (Get-WmiObject win32_userprofile | select-object Localpath, SID | where-object Localpath -eq 'C:\Users\sidTest' | Select-Object SID).SID
            (Convert-SID -Sid $circlecisid) | Should -match 'sidTest'
        }
    }

    Context 'Convert-UserName Function' {
        It 'Convert-UserName' {
            $circlecisid = (Get-WmiObject win32_userprofile | select-object Localpath, SID | where-object Localpath -eq 'C:\Users\sidTest' | Select-Object SID).SID
            (Convert-UserName -user:('sidTest')) | Should -match $circlecisid
        }
    }

    Context 'Test-UsernameOrSID Function' -Skip {
        # Tested in Migration Tests
        It 'Test-UsernameOrSID' {

        }
    }

    Context 'Restart-ComputerWithDelay Function' -Skip {
        # Test Manually
        It 'Restart-ComputerWithDelay' {
        }
    }

    Context 'Validates that the Registry Hive Permissions are correct, given a username' {
        It 'Should return true when a users hive permissions are correct' {
            $datUserTrue = "ADMU_DATPermission" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            InitUser -UserName $datUserTrue -Password $Password

            # Test NTUser dat permissions
            $NTUser = Test-DATFilePermission -Path "C:\Users\$datUserTrue\NTUser.DAT" -username $datUserTrue
            # Test UsrClass dat permissions
            $UsrClass = Test-DATFilePermission -Path "C:\Users\$datUserTrue\AppData\Local\Microsoft\Windows\UsrClass.dat" -username $datUserTrue
            $NTUser | Should -Be $true
            $UsrClass | Should -Be $true
        }
        It 'Should return false when a users hive permissions are correct' {
            $datUserFalse = "ADMU_DATPermission" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            InitUser -UserName $datUserFalse -Password $Password
            $filePaths = @("C:\Users\$datUserFalse\AppData\Local\Microsoft\Windows\UsrClass.dat", "C:\Users\$datUserFalse\NTUser.DAT")
            $requiredAccounts = @("SYSTEM", "Administrators", "$datUserFalse")
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
                    $NTUser = Test-DATFilePermission -Path $FilePath -username $datUserFalse
                    Write-Host "this should be false: $NTUser"
                    $NTUser | Should -Be $false

                    # Retrieve new explicit set of permissions
                    $FileACL = Get-Acl $FilePath

                    # Add the rule again
                    $FileACL.SetAccessRule($ruleToRemove)
                    # Set ACL on file again
                    Set-Acl $FilePath -AclObject $FileACL
                    $NTUser = Test-DATFilePermission -Path $FilePath -username $datUserFalse
                    Write-Host "this should be true: $NTUser"
                    # Test UsrClass dat permissions
                    $NTUser | Should -Be $true
                }
            }
        }
    }
}
