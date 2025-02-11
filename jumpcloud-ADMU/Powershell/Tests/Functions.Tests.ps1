BeforeAll {
    # Install JCAgent on this build server:
    If ($env:CI) {
        . $PSScriptRoot\..\..\..\Deploy\TestSetup.ps1 -TestOrgConnectKey $env:PESTER_CONNECTKEY
    }
    Write-Host "Script Location: $PSScriptRoot"
    # setting test variables
    . $PSScriptRoot\SetupAgent.ps1
    Write-Host "Running Connect-JCOnline"
    Connect-JCOnline -JumpCloudApiKey $env:PESTER_APIKEY -JumpCloudOrgId $env:PESTER_ORGID -Force
    Function Get-WindowsDrive {
        return 'drive'
    }
    # Import Private Functions:
    $Private = @( Get-ChildItem -Path "$PSScriptRoot/../Private/*.ps1" -Recurse)
    Foreach ($Import in $Private) {
        Try {
            . $Import.FullName
        } Catch {
            Write-Error -Message "Failed to import function $($Import.FullName): $_"
        }
    }
}
Describe 'Functions' {
    BeforeAll {
        Mock Get-WindowsDrive { return "C:" }
    }
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
    Context 'Set-PTA/FTA Test' {
        BeforeAll {
            # Import /Deploy/uwp_jcadmu.ps1 and use the function Set-FTA
            . $PSScriptRoot\..\..\..\Deploy\uwp_jcadmu.ps1
        }
        It 'Set-FTA should be changed after migration' {
            $protocol = "http"
            $fileType = ".txt"

            Set-FTA "wordpad" $fileType
            Set-PTA -ProgId "notepad" -Protocol $protocol

            $fta = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($fileType)\UserChoice"
            $pta = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($protocol)\UserChoice"
            # Write out the contents of the FTA and PTA
            Write-Host "FTA: $($fta)"
            Write-Host "PTA: $($pta)"
            # Check if programId is wordpad
            $fta.ProgId | Should -Contain "wordpad"
            $pta.ProgId | Should -Contain "notepad"

        }
    }
    Context 'Test-JumpCloudUsername Function' {
        It 'Valid Username Returns True' {
            # Get the first user
            $user = Get-JcSdkUser | Select-Object -First 1
            # Test username w/o modification
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $user.Username
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
            # toUpper
            $upper = ($user.Username).ToUpper()
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $upper
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
            # to lower
            $lower = ($user.Username).ToLower()
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $lower
            $testResult | Should -Be $true
            $userID | Should -Be $user.Id
        }
        It 'Invalid Username Returns False' {
            # Get the first user
            $user = Get-JcSdkUser | Select-Object -First 1
            # Append random string to username
            $newUsername = $user.Username + "jdksf45kjfds"
            # Test function
            $testResult, $userID, $FoundUsername, $FoundSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $env:PESTER_APIKEY -Username $newUsername
            $testResult | Should -Be $false
            $userID | Should -Be $null
        }
    }

    Context 'Set-JCUserToSystemAssociation Function' {
        # Set-JCUserToSystemAssociation should take USERID as input validated with Test-JumpCloudUsername
        BeforeAll {
            $OrgSelection, $MTPAdmin = Get-MtpOrganization -apiKey $env:PESTER_APIKEY
            $OrgName = "$($OrgSelection[1])"
            $OrgID = "$($OrgSelection[0])"
            Mock Get-WindowsDrive { return "C:" }
            $windowsDrive = Get-WindowsDrive

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
            $users = Get-JCSdkUser
            if ("$($user.JCUsername)" -in $users.Username) {
                $existing = $users | Where-Object { $_.username -eq "$($user.JCUsername)" }
                Write-Host "Found JumpCloud User, $($existing.Id) removing..."
                Remove-JcSdkUser -Id $existing.Id
            }
            $GeneratedUser = New-JcSdkUser -Email:("$($user1)@jumpcloudadmu.com") -Username:("$($user1)") -Password:("$($Password)")
            # Begin Test
            Get-JCAssociation -Type user -Id:($($GeneratedUser.Id)) | Remove-JCAssociation -Force
            $bind = Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcOrgId $OrgID -JcUserID $GeneratedUser.Id
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
            $bind = Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcOrgId $OrgID -JcUserID $GeneratedUser.Id -BindAsAdmin $true
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
            { Set-JCUserToSystemAssociation -JcApiKey $env:PESTER_APIKEY -JcUserID $GeneratedUser.Id -ErrorAction Stop } | Should -Throw
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
            { New-LocalUserProfile -username:('UserDoesNotExist') -ErrorAction Stop } | Should -Throw
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

    Context 'Get-SecurityIdentifier Function' {
        It 'Tests that Get-SecurityIdentifier returns a valid regex matched SID for the current user' {
            # SID of current user should match SID regex pattern
            $currentUser = $(whoami) -replace "$(hostname)\\", ("")
            $currentSID = Get-SecurityIdentifier -User:($currentUser)
            $currentSID | Should -Match "^S-\d-\d+-(\d+-){1,14}\d+$"
        }
    }

    Context 'Set-UserRegistryLoadState Function' -Skip {
        # Unload and load user registry - we are testing this in Migration tests
        It 'Load ' {
            # $circlecisid = (Get-SecurityIdentifier -User:'circleci')
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

    Context 'Test-LocalUsername Function' {
        It 'Test-LocalUsername - exists' {
            # This test requires a windows device to create the get the user
            $userName = "TesterUser12345"
            $password = "TesterPassword12345!!"
            $newUserPassword = ConvertTo-SecureString -String "$($Password)" -AsPlainText -Force
            New-localUser -Name "$($UserName)" -password $newUserPassword -Description "Created By JumpCloud ADMU"

            # Get Win32 Profiles to merge data with valid SIDs
            $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
            # get localUsers (can contain users who have not logged in yet/ do not have a SID)
            $nonSIDLocalUsers = Get-LocalUser
            Test-LocalUsername -username $userName -win32UserProfiles $win32UserProfiles -localUserProfiles $nonSIDLocalUsers | Should -Be $true
        }

        It 'Test-LocalUsername - does not exist' {

            # Get Win32 Profiles to merge data with valid SIDs
            $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
            # get localUsers (can contain users who have not logged in yet/ do not have a SID)
            $nonSIDLocalUsers = Get-LocalUser
            Test-LocalUsername -username 'blazarz' -win32UserProfiles $win32UserProfiles -localUserProfiles $nonSIDLocalUsers | Should -Be $false
        }
    }

    Context 'Install-JumpCloudAgent Function' {
        BeforeAll {
            Mock Get-WindowsDrive { Return "C:" }
            $windowsDrive = Get-WindowsDrive
            $AGENT_INSTALLER_URL = "https://cdn02.jumpcloud.com/production/jcagent-msi-signed.msi"
            $AGENT_INSTALLER_PATH
            $AGENT_PATH = Join-Path ${env:ProgramFiles} "JumpCloud"
            $AGENT_CONF_PATH = "$($AGENT_PATH)\Plugins\Contrib\jcagent.conf"
            $AGENT_INSTALLER_PATH = "$windowsDrive\windows\Temp\JCADMU\jcagent-msi-signed.msi"

            # now go install the agent
            Install-JumpCloudAgent -AGENT_INSTALLER_URL:($AGENT_INSTALLER_URL) -AGENT_INSTALLER_PATH:($AGENT_INSTALLER_PATH) -AGENT_CONF_PATH:($AGENT_CONF_PATH) -JumpCloudConnectKey:($JumpCloudConnectKey) -AGENT_PATH:($AGENT_PATH) -AGENT_BINARY_NAME:($AGENT_BINARY_NAME)
        }

        It 'Install-JumpCloudAgent - Verify Download JCAgent Path' {
            Test-path 'C:\Windows\Temp\JCADMU\jcagent-msi-signed.msi' | Should -Be $true
        }

        It 'Install-JumpCloudAgent - Verify Install JCAgent' {
            Get-Service -Name "jumpcloud-agent" | Should -Not -Be $null
        }
    }

    Context 'Convert-SecurityIdentifier Function' {
        BeforeAll {
            $newUserPassword = ConvertTo-SecureString -String 'Temp123!' -AsPlainText -Force
            New-localUser -Name 'sidTest' -password $newUserPassword -Description "Created By JumpCloud ADMU tests"
            New-LocalUserProfile -username:('sidTest')
        }
        It 'Convert-SecurityIdentifier - circleci SID' {
            $circlecisid = (Get-WmiObject win32_userprofile | select-object Localpath, SID | where-object Localpath -eq 'C:\Users\sidTest' | Select-Object SID).SID
            (Convert-SecurityIdentifier -Sid $circlecisid) | Should -match 'sidTest'
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
    Context 'Test Set-ADMUScheduledTask' {
        BeforeAll {
            $scheduledTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -ne "Disabled" -and $_.state -ne "Running" }
            Set-ADMUScheduledTask -op "disable" -scheduledTasks $scheduledTasks
        }
        It 'Should disabled tasks' {
            # Disable tasks that are ready to run
            $afterDisable = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -eq "Disabled" }
            # Compare $scheduledTasks and $afterDisable state should not be equal
            $scheduledTasks | ForEach-Object {
                $task = $_
                # Check that the task is disabled
                $afterDisable | Where-Object { $_.TaskName -eq $task.TaskName -and $_.State -eq "Disabled" } | Should -Not -BeNullOrEmpty
            }
        }
        It 'Should Enable tasks' {
            Set-ADMUScheduledTask -op "enable" -scheduledTasks $scheduledTasks
            # Validate that the tasks are enabled
            $afterEnable = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "*\Microsoft\Windows*" -and $_.State -eq "Ready" }
            # Compare $scheduledTasks and $afterDisable state should not be equal
            $scheduledTasks | ForEach-Object {
                $task = $_
                # Check that the task is disabled
                $afterEnable | Where-Object { $_.TaskName -eq $task.TaskName -and $_.State -eq "Ready" } | Should -Not -BeNullOrEmpty
            }
        }
    }
    Context 'Validates the functionailty of the Set-FileAttribute and associated functions' {
        BeforeAll {
            # create some file to test with:
            $content = "placeholder text"
            # save the file
            $content | Out-File "C:\Windows\Temp\content.txt"
            $contentFilePath = "C:\Windows\Temp\content.txt"
        }
        It 'Validates the function Test-FileAttribute should reuturn true/ falst given some attribute type' {
            # using attrib, set the file associations to hidden and archive
            Attrib +h +a $contentFilePath
            # validate that the test function will return true for both attributes and false for another
            Test-FileAttribute -ProfilePath $contentFilePath -Attribute "Hidden" | Should -Be $true
            Test-FileAttribute -ProfilePath $contentFilePath -Attribute "Archive" | Should -Be $true
            Test-FileAttribute -ProfilePath $contentFilePath -Attribute "System" | Should -Be $false
        }
        It 'Validates that a file attribute can be added to a file with the Set-FileAttribute function' {
            Set-FileAttribute -ProfilePath $contentFilePath -Attribute "System" -Operation "Add" | Should -Be $true
            Test-FileAttribute -ProfilePath $contentFilePath -Attribute "System" | Should -Be $true
        }
        It 'Validates that a file attribute can be removed from a file with the Set-FileAttribute function' {
            # when we remove the returned bool should be false because Test-FileAttribute returns "false" if the attribute does not exist
            Set-FileAttribute -ProfilePath $contentFilePath -Attribute "System" -Operation "Remove" | Should -be $false
            Test-FileAttribute -ProfilePath $contentFilePath -Attribute "System" | Should -Be $false
        }

    }
    Context 'Validates that the  Registry Hive Permissions are correct, given a username' {
        It 'Should return true when a users ntfs permissions are correct' {
            $datUserTrue = "ADMU_dat_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $password = '$T#st1234'
            InitUser -UserName $datUserTrue -Password $Password

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
            InitUser -UserName $datUserFalse -Password $Password
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

    # Test for Test-UserFolderRedirect

}
