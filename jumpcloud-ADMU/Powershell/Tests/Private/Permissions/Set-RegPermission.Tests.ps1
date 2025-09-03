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

    Context "SID Translation Tests" {
        It "Falls back to SID string and throws if SID cannot be translated" {
            # This test expects that addAccessRule will throw if the SID does not exist on some system
            # Arrange
            $fakeSID = 'S-1-5-21-0000000000-0000000000-0000000000-1234'
            $targetSID = 'S-1-5-21-0000000000-0000000000-0000000000-5678'
            $testPath = "$env:TEMP\testfile.txt"
            New-Item -Path $testPath -ItemType File -Force | Out-Null
            # Act
            { Set-RegPermission -SourceSID $fakeSID -TargetSID $targetSID -FilePath $testPath } | Should -Throw 'Exception calling "AddAccessRule" with "1" argument(s): "Some or all identity references could not be translated."'
            # Cleanup
            Remove-Item $testPath -Force
        }
        It "Create a fake domain profile and it should still copy ACLs while off the domain" {
            # set some fake domain profile SID:
            $domainSID = "S-1-12-1-1616384916-1297768490-51239584-3993624738"
            $profileImagePath = "C:\Users\FakeDomainUser"
            # create a new entry in the registry for the fake domain profile
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$domainSID"
            New-Item -Path $regPath -Force | Out-Null
            Set-ItemProperty -Path $regPath -Name "ProfileImagePath" -Value $profileImagePath
            # convert the SID to bytes and set as the "Sid" property in the profile:
            $Bytes = [System.Text.Encoding]::Unicode.GetBytes($domainSID)
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$domainSID" -Name "Sid" -Type Binary -Value $Bytes
            # set the Flags, FullProfile, State properties
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$domainSID" -Name "Flags" -Type DWord -Value 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$domainSID" -Name "FullProfile" -Type DWord -Value 1
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$domainSID" -Name "State" -Type DWord -Value 0

            # create the ProfileImagePath if it does not exist:
            # Create test directory and files
            if (Test-Path $profileImagePath) { Remove-Item $profileImagePath -Recurse -Force }
            New-Item -ItemType Directory -Path $profileImagePath | Out-Null
            New-Item -ItemType File -Path (Join-Path $profileImagePath "testfile.txt") | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $profileImagePath "subdir") | Out-Null
            New-Item -ItemType File -Path (Join-Path $profileImagePath "subdir\subfile.txt") | Out-Null

            # Set a new acl rule for each testfile, subdir and subdir\subfile.txt
            $items = Get-ChildItem -Path $profileImagePath -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $acl = Get-Acl -Path $item.FullName
                $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($domainSID)))
                $sid = New-Object System.Security.Principal.SecurityIdentifier($domainSID)
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, "FullControl", "Allow")
                $acl.AddAccessRule($accessRule)
                Set-Acl -Path $item.FullName -AclObject $acl
            }

            # init some new user:
            $testUsername = "sidTranslate3"
            Initialize-TestUser -Username $testUsername -password "Temp123!Temp123!"
            $targetSID = Test-UsernameOrSID -usernameOrSid $testUsername


            Write-Host "####################"
            Write-Host "Test Directory: $profileImagePath"
            Write-Host "Source SID: $domainSID"
            Write-Host "Target SID: $targetSID"
            Write-Host "Current Owner: $((Get-Acl $profileImagePath).Owner)"
            Write-Host "####################"
            # Run SetRegPermission:
            Set-RegPermission -SourceSID $domainSID -TargetSID $targetSID -FilePath $profileImagePath

            $items = Get-ChildItem -Path $profileImagePath -Recurse -Force
            foreach ($item in $items) {
                $acl = Get-Acl -Path $item.FullName
                $acl.Owner | Should -Be ((New-Object System.Security.Principal.SecurityIdentifier($targetSID)).Translate([System.Security.Principal.NTAccount]).Value)
                $acl.Access.IdentityReference | Should -Contain ((New-Object System.Security.Principal.SecurityIdentifier($targetSID)).Translate([System.Security.Principal.NTAccount]).Value)

            }
        }
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

            # set the owner of the $testDir to the $sourceSID
            $acl = Get-Acl $testDir
            $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($sourceSID)))
            Set-Acl -Path $testDir -AclObject $acl
            Write-Host "####################"
            Write-Host "Test Directory: $testDir"
            Write-Host "Source SID: $sourceSID"
            Write-Host "Target SID: $targetSID"
            Write-Host "Current Owner: $((Get-Acl $testDir).Owner)"
            Write-Host "####################"
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

        It "Should add the targetAccount as a member of the ACL if it does not already exist" {

            Set-RegPermission -SourceSID $sourceSID -TargetSID $targetSID -FilePath $testDir
            # the targetAccount should be added to the ACL
            $acl = Get-Acl $testDir
            $targetAccount = (New-Object System.Security.Principal.SecurityIdentifier($targetSID)).Translate([System.Security.Principal.NTAccount]).Value
            $acl.Access | Where-Object { $_.IdentityReference -eq $targetAccount } | Should -Not -BeNullOrEmpty
        }

    }
    It "Should change the permission set for hidden files and folders" {
        # init a user profile for testing:
        # sample password
        $tempPassword = "Temp123!"
        # username to migrate
        $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # username to migrate to
        $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # username to migrate to

        # Initialize-TestUser
        Initialize-TestUser -username $userToMigrateTo -password $tempPassword
        Initialize-TestUser -username $userToMigrateFrom -password $tempPassword

        #Check SID
        $UserSID = Get-LocalUser -Name $userToMigrateFrom | Select-Object -ExpandProperty SID
        $UserSIDNew = Get-LocalUser -Name $userToMigrateTo | Select-Object -ExpandProperty SID

        # create a hidden folder and file in the appdata/local/Programs directory
        $appDataPath = "C:\Users\$($userToMigrateFrom)\AppData\Local\Programs"
        $hiddenFolderPath = Join-Path -Path $appDataPath -ChildPath "HiddenFolder"
        $hiddenFilePath = Join-Path -Path $appDataPath -ChildPath "HiddenFile.txt"
        New-Item -ItemType Directory -Path $hiddenFolderPath -Force | Out-Null
        New-Item -ItemType File -Path $hiddenFilePath -Force | Out-Null
        # set the hidden attribute
        $hiddenFolder = Get-Item $hiddenFolderPath
        $hiddenFile = Get-Item $hiddenFilePath
        $hiddenFolder.Attributes = $hiddenFolder.Attributes -bor [System.IO.FileAttributes]::Hidden
        $hiddenFile.Attributes = $hiddenFile.Attributes -bor [System.IO.FileAttributes]::Hidden

        # set the ownership to the user to migrate from
        $acl = Get-Acl $hiddenFolderPath
        $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($UserSID)))
        Set-Acl -Path $hiddenFolderPath -AclObject $acl
        $acl = Get-Acl $hiddenFilePath
        $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($UserSID)))
        Set-Acl -Path $hiddenFilePath -AclObject $acl

        # now perform the registry clone and change
        $userProfilePath = "C:\Users\$($userToMigrateFrom)"
        $regPermStopwatchNew = [System.Diagnostics.Stopwatch]::StartNew()
        Set-RegPermission -SourceSID $UserSID -TargetSID $UserSIDNew -FilePath $userProfilePath
        $regPermStopwatchNew.Stop()
        $newTime = $regPermStopwatchNew.Elapsed.TotalSeconds

        Write-Host "Set-RegPermission time: $newTime seconds"

        # test for the following directories in AppData: Roaming, Local
        foreach ($subDir in @("Roaming", "Local")) {
            $appDataPath = Join-Path -Path "C:\Users\$($userToMigrateFrom)\AppData" -ChildPath $subDir
            $appDataAcl = Get-Acl $appDataPath
            $appDataAcl.Owner | Should -Be ((New-Object System.Security.Principal.SecurityIdentifier($UserSIDNew)).Translate([System.Security.Principal.NTAccount]).Value)
        }

        #for each ($item in @($hiddenFolderPath, $hiddenFilePath)) {
        foreach ($item in @($hiddenFolderPath, $hiddenFilePath)) {
            $acl = Get-Acl $item
            $acl.Owner | Should -Be ((New-Object System.Security.Principal.SecurityIdentifier($UserSIDNew)).Translate([System.Security.Principal.NTAccount]).Value)
            $acl.Access | Where-Object { $_.IdentityReference -eq ((New-Object System.Security.Principal.SecurityIdentifier($UserSIDNew)).Translate([System.Security.Principal.NTAccount]).Value) -and $_.FileSystemRights -eq "FullControl" } | Should -Not -BeNullOrEmpty
            # Check if the item is still hidden
            $itemAttributes = (Get-Item $item -Force).Attributes
            $itemAttributes -band [System.IO.FileAttributes]::Hidden | Should -Be ([System.IO.FileAttributes]::Hidden)
        }


    }

    Context "Permission performance metrics" {
        BeforeEach {
            # init a user profile for testing:
            # sample password
            $tempPassword = "Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userOldFunction = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userNewFunction = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            Initialize-TestUser -username $userOldFunction -password $tempPassword
            Initialize-TestUser -username $userNewFunction -password $tempPassword

            #Check SID
            $UserSID = Get-LocalUser -Name $userToMigrateFrom | Select-Object -ExpandProperty SID
            $UserSIDOldFunction = Get-LocalUser -Name $userOldFunction | Select-Object -ExpandProperty SID
            $UserSIDNewFunction = Get-LocalUser -Name $userNewFunction | Select-Object -ExpandProperty SID
        }
        It "Should perform directory permission clone faster than the pervious version of the Set-RegPermission function" {
            # get the version of the set-RegPermission v2.8.7 from github:
            $url = "https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/refs/heads/v2.8.7/jumpcloud-ADMU/Powershell/Private/Permissions/Set-RegPermission.ps1"
            $setRegPermissionOld = Invoke-WebRequest -Uri $url -UseBasicParsing
            $setRegPermissionOldContent = $setRegPermissionOld.Content
            # replace the function name to Set-RegPermissionOld
            $setRegPermissionOldContent = $setRegPermissionOldContent -replace "function Set-RegPermission", "function Set-RegPermissionOld"
            # write
            $setRegPermissionOldPath = Join-Path -Path $env:TEMP "Set-RegPermission-v2.8.7.ps1"
            Set-Content -Path $setRegPermissionOldPath -Value $setRegPermissionOldContent -Force
            $setRegPermissionOldContent | Select-String "function Set-RegPermissionOld" | Should -Not -BeNullOrEmpty
            if (-not (Test-Path $setRegPermissionOldPath)) {
                throw "Set-RegPermission-v2.8.7.ps1 not found at $setRegPermissionOldPath"
            }            # import the v2.8.7 version of Set-RegPermission
            Write-Host "Importing Set-RegPermissionOld from $setRegPermissionOldPath"
            . $setRegPermissionOldPath
            Get-Command Set-RegPermissionOld | Should -Not -BeNullOrEmpty

            $regPermStopwatchOld = [System.Diagnostics.Stopwatch]::StartNew()
            $userProfilePath = "C:\Users\$($userToMigrateFrom)"
            $NewSPN_Name = $env:COMPUTERNAME + '\' + $userOldFunction
            $Acl = Get-Acl $userProfilePath
            $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule($NewSPN_Name, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $Acl.SetAccessRule($Ar)
            $Acl | Set-Acl -Path $userProfilePath

            Set-RegPermissionOld -sourceSID $UserSID -targetSID $UserSIDOldFunction -filePath $userProfilePath
            $regPermStopwatchOld.Stop()

            # perform the same operation with the new Set-RegPermission
            # re-import the Set-RegPermission function
            $regPermStopwatchNew = [System.Diagnostics.Stopwatch]::StartNew()
            Set-RegPermission -SourceSID $UserSID -TargetSID $UserSIDNewFunction -FilePath $userProfilePath
            $regPermStopwatchNew.Stop()

            # Compare the times:
            $oldTime = $regPermStopwatchOld.Elapsed.TotalSeconds
            $newTime = $regPermStopwatchNew.Elapsed.TotalSeconds
            $performanceIncrease = (($oldTime - $newTime) / $oldTime) * 100
            Write-Host ("Performance increase: {0:N2}%" -f $performanceIncrease)
            Write-Host "Old Set-RegPermission time: $oldTime seconds"
            Write-Host "New Set-RegPermission time: $newTime seconds"
            $newTime | Should -BeLessOrEqual $oldTime

        }

    }
}
