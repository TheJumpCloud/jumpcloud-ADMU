BeforeAll {
    Write-Host "Script Location: $PSScriptRoot"
    Write-Host "Dot-Sourcing Start-Migration Script"
    . $PSScriptRoot\..\Start-Migration.ps1
    Connect-JCOnline -JumpCloudApiKey $env:JCApiKey -JumpCloudOrgId $env:JCOrgId -Force
}
Describe 'Functions' {
    Context 'Show-Result Function'{
    }

    Context 'Test-RegistryValueMatch Function'{
        It 'Value matches' {
            Test-RegistryValueMatch -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Value 'Public' -stringmatch 'Public' | Should -Be $true
        }

        It 'Value does not match' {
            Test-RegistryValueMatch -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Value 'Public' -stringmatch 'Private' | Should -Be $false
        }
    }
    Context 'Test-JumpCloudUsername Function' {
        It 'Valid Username Returns True'{
            # Get the first user
            $user = Get-JcSdkUser | Select-Object -First 1
            # Test function
            $testResult, $userID = Test-JumpCloudUsername -JumpCloudApiKey $env:JCApiKey -Username $user.Username
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
        }
        It 'Invalid Username Returns False'{
            # Get the first user
            $user = Get-JcSdkUser | Select-Object -First 1
            # Append random string to username
            $newUsername = $user.Username + "jdksf45kjfds"
            # Test function
            $testResult, $userID = Test-JumpCloudUsername -JumpCloudApiKey $env:JCApiKey -Username $newUsername
            $testResult | Should -Be $false
            $userID | Should -Be $null
        }
    }

    Context 'BindUsernameToJCSystem Function'{
        It 'User exists' {
            # Generate New User
            $Password = "Temp123!"
            $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # If User Exists, remove from the org
            $users = Get-JCSDKUser
                if ("$($user.JCUsername)" -in $users.Username)
                {
                    $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                    Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                    Remove-JcSdkUser -Id $existing.Id
                }
            $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
            # Begin Test
            Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
            $bind = BindUsernameToJCSystem -JcApiKey $env:JCApiKey -JumpCloudUserName $user1
            $bind | Should -Be $true
            ((Get-JCAssociation -Type:user -Id:($($GeneratedUser.Id))).id).count | Should -Be '1'
            # Clean Up
            Remove-JcSdkUser -Id $GeneratedUser.Id
        }

        It 'APIKey not valid' {
            $bind = BindUsernameToJCSystem -JcApiKey '1234122341234234123412341234123412341234' -JumpCloudUserName 'jsmith'
            $bind | Should -Be $false
        }

        It 'Agent not installed' -skip{
            #TODO: Is this test necessary, it breaks the migration tests
            if ((Test-Path -Path "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf") -eq $True) {
                Remove-Item "C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
              }
            {BindUsernameToJCSystem -JcApiKey $env:JCApiKey -JumpCloudUserName 'jsmith' -ErrorAction Stop} | Should -Throw
        }
    }

    Context 'DenyInteractiveLogonRight Function'{
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

    Context 'Register-NativeMethod Function'{
    }

    Context 'Add-NativeMethod Function'{
    }

    Context 'New-LocalUserProfile Function'{
        It 'User created and exists on system' {
            $newUserPassword = ConvertTo-SecureString -String 'Temp123!' -AsPlainText -Force
            New-localUser -Name 'testjc' -password $newUserPassword -Description "Created By JumpCloud ADMU tests"
            New-LocalUserProfile -username:('testjc')
            Test-Path -Path 'C:\Users\testjc' | Should -Be $true
        }

        It 'User does not exist on system and throws exception' {
            {New-LocalUserProfile -username:('userdoesntexist') -ErrorAction Stop} | Should -Throw
        }
    }

    Context 'Remove-LocalUserProfile Function'{
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
            {Remove-LocalUserProfile -username:('randomusernamethatdoesntexist') -ErrorAction Stop} | Should -Throw
        }
    }

    Context 'Set-ValueToKey Function'{
        It 'Value is set on existing key' {
            Set-ValueToKey -registryRoot LocalMachine -keyPath 'SYSTEM\Software' -name '1' -value '1' -regValueKind DWord
            Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\Software\' -Name '1' | Should -Be '1'
        }
    }

    Context 'New-RegKey Function'{
        It 'Key is created' {
            New-RegKey -keyPath 'SYSTEM\1' -registryRoot LocalMachine
            test-path 'HKLM:\SYSTEM\1' | Should -Be $true
        }
    }

    Context 'Get-SID Function'{
        It 'Profile exists and sid returned' {
            # TODO: testing that the SID length is 44 isn't testing the Get-SID function, nor can we expect the SID length to be 44 each time.
            # $circlecisid = (Get-WmiObject win32_userprofile | select-object Localpath, SID | where-object Localpath -eq 'C:\Users\circleci'| Select-Object SID).SID.Length | Should -Be '44'
            # Get-SID -User:'circleci' -eq $circlecisid | Should -Be $true
            # TODO: Agree on new test
            # SID of circleCI user should match SID regex pattern
            Get-SID -User:'circleci' -cnotmatch "^S-\d-\d+-(\d+-){1,14}\d+$" | Should -Be $true
        }
    }

    Context 'Set-UserRegistryLoadState Function'{
        It 'Load ' {
            # $circlecisid = (Get-SID -User:'circleci')
            # Set-UserRegistryLoadState -op Load -ProfilePath 'C:\Users\circleci\' -UserSid $circlecisid
            # $path = 'HKU:\' $circlecisid_'_a
            # Test-Path -Path 'HKU:\$($circlecisid)'
        }

        It 'Unload' -skip{

        }
    }

    Context 'Test-UserRegistryLoadState Function'{
    }

    Context 'Backup-RegistryHive Function'{
    }

    Context 'Get-ProfileImagePath Function'{
    }

    Context 'Get-WindowsDrive Function'{
        It 'Get-WindowsDrive - C' {
            Get-WindowsDrive | Should -Be "C:"
        }
    }

    Context 'Write-ToLog Function'{

        It 'Write-ToLog - ' {
		    if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                    remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
                Write-ToLog -Message:('Log is created - test.') -Level:('Info')
                $log='C:\windows\Temp\jcAdmu.log'
                $log | Should -exist
        }

        It 'Write-ToLog - Log is created' {
		    if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                    remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
                Write-ToLog -Message:('Log is created - test.') -Level:('Info')
                $log='C:\windows\Temp\jcAdmu.log'
                $log | Should -exist
        }

        It 'Write-ToLog - ERROR: Log entry exists' {
		    if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
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
		    if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                   remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
               Write-ToLog -Message:('Test Warning Log Entry.') -Level:('Warn')
               $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
               $Log.Contains('WARNING: Test Warning Log Entry.') | Should -Be $true
        }

        It 'Write-ToLog - INFO: Log entry exists' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
                    remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
            }
                Write-ToLog -Message:('Test Info Log Entry.') -Level:('Info')
                $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
                $Log.Contains('INFO: Test Info Log Entry.') | Should -Be $true
                remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
    }

    Context 'Remove-ItemIfExist Function'{

        It 'Remove-ItemIfExist - Does Exist c:\windows\temp\test\' {
            if(Test-Path 'c:\windows\Temp\test\') {Remove-Item 'c:\windows\Temp\test' -Recurse -Force}
            New-Item -ItemType directory -path 'c:\windows\Temp\test\'
            New-Item 'c:\windows\Temp\test\test.txt'
            Remove-ItemIfExist -Path 'c:\windows\Temp\test\' -Recurse
            Test-Path 'c:\windows\Temp\test\' | Should -Be $false
        }

        It 'Remove-ItemIfExist - Fails c:\windows\temp\test\' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force}
            Mock Remove-ItemIfExist {Write-ToLog -Message ('Removal Of Temp Files & Folders Failed') -Level Warn}
            Remove-ItemIfExist -Path 'c:\windows\Temp\test\'
            $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
            $Log.Contains('Removal Of Temp Files & Folders Failed') | Should -Be $true
        }
    }

    Context 'Test-ProgramInstalled Function'{

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

    Context 'Uninstall-Program Function'{

        It 'Uninstall - aws command line interface' -Skip {
            uninstall-program -programname 'AWS Command Line Interface'
            start-sleep -Seconds 5
            Test-ProgramInstalled -programName 'AWS Command Line Interface' | Should -Be $false
        }
    }

    Context 'Start-NewProcess Function'{

        It 'Start-NewProcess - Notepad' {
            Start-NewProcess -pfile:('c:\windows\system32\notepad.exe') -Timeout 1000
            (Get-Process -Name 'notepad') -ne $null | Should -Be $true
            Stop-Process -Name "notepad"
        }

        It 'Start-NewProcess & end after 2s timeout - Notepad ' {
            if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true){
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

    Context 'Test-IsNotEmpty Function'{

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

    Context 'Test-Is40chars Function'{

        It 'Test-Is40chars - $null' {
            Test-Is40chars -field $null | Should -Be $false
        }

        It 'Test-Is40chars - 39 Chars' {
            Test-Is40chars -field '111111111111111111111111111111111111111' | Should -Be $false
        }

        It 'Test-Is40chars - 40 Chars' {
            Test-Is40chars -field '1111111111111111111111111111111111111111' | Should -Be $true
        }
    }

    Context 'Test-HasNoSpace Function'{

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

    Context 'Add-LocalUser Function'{

        It 'Add-LocalUser - testuser to Users ' {
            net user testuser /delete | Out-Null
            net user testuser Temp123! /add
            Remove-LocalGroupMember -Group "Users" -Member "testuser"
            Add-LocalGroupMember -SID S-1-5-32-545 -Member 'testuser'
            (([ADSI]"WinNT://./Users").psbase.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('AdsPath') } ) -match 'testuser' | Should -Be $true
        }
    }

    Context 'Test-Localusername Function'{

        It 'Test-Localusername - exists' {

            Test-Localusername -field 'circleci' | Should -Be $true
        }

        It 'Test-Localusername - does not exist' {

            Test-Localusername -field 'blazarz' | Should -Be $false
        }
    }

    Context 'Test-Domainusername Function'{
# Requires domainjoined system
        It 'Test-Domainusername - exists' -skip {

            Test-Domainusername -field 'bob.lazar' | Should -Be $true
        }

        It 'Test-Domainusername - does not exist' {

            Test-Domainusername -field 'bob.lazarz' | Should -Be $false
        }
    }

    Context 'Install-JumpCloudAgent Function'{
    #Already installed on circleci
        It 'Install-JumpCloudAgent - Verify Download JCAgent prereq Visual C++ 2013 x64' -skip {
            Test-path 'C:\Windows\Temp\JCADMU\vc_redist.x64.exe' | Should -Be $true
        }
    #Already installed on circleci
        It 'Install-JumpCloudAgent - Verify Download JCAgent prereq Visual C++ 2013 x86' -skip {
            Test-path 'C:\Windows\Temp\JCADMU\vc_redist.x86.exe' | Should -Be $true
        }

        It 'Install-JumpCloudAgent - Verify Download JCAgent' {
            Test-path 'C:\Windows\Temp\JCADMU\JumpCloudInstaller.exe' | Should -Be $true
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

    Context 'Get-NetBiosName Function'{
# Requires domainjoined system
        It 'Get-NetBiosName - JCADB2' -Skip {
            Get-NetBiosName | Should -Be 'JCADB2'
        }
    }

    Context 'Convert-SID Function'{
        It 'Convert-SID - circleci SID' {
            $circlecisid = (Get-WmiObject win32_userprofile | select-object Localpath, SID | where-object Localpath -eq 'C:\Users\circleci'| Select-Object SID).SID
            (Convert-SID -Sid $circlecisid) | Should -match 'circleci'
        }
    }

    Context 'Convert-UserName Function'{
        It 'Convert-UserName' {
            $circlecisid = (Get-WmiObject win32_userprofile | select-object Localpath, SID | where-object Localpath -eq 'C:\Users\circleci'| Select-Object SID).SID
            (Convert-UserName -user:('circleci')) | Should -match $circlecisid
        }
    }

    Context 'Test-UsernameOrSID Function'{
        It 'Test-UsernameOrSID' {

        }
    }

    Context 'Invoke-JumpCloudAgentInstall Function' -Skip{
        It 'Invoke-JumpCloudAgentInstall' {
        }
    }

    Context 'Restart-ComputerWithDelay Function' -Skip{
        It 'Restart-ComputerWithDelay' {
        }
    }
}
