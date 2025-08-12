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
            $setRegPermissionV2 = Invoke-WebRequest -Uri $url -UseBasicParsing
            $setRegPermissionOldContent = $setRegPermissionOldContent.Content
            # replace the function name to Set-RegPermissionOld
            $setRegPermissionOldContent = $setRegPermissionOldContent -replace "function Set-RegPermission", "function Set-RegPermissionOld"
            # write
            $setRegPermissionOldPath = Join-Path -Path $HOME "Set-RegPermission-v2.8.7.ps1"
            Set-Content -Path $setRegPermissionOldPath -Value $setRegPermissionOldContent -Force

            # import the v2.8.7 version of Set-RegPermission
            . $setRegPermissionOldPath

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
