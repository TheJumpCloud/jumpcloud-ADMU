BeforeAll {
    # import functions from start migration
    write-host "Importing Reverse-Migrate Script:"
    . $PSScriptRoot\..\Reverse-Migrate.ps1
    . $PSScriptRoot\..\Start-Migration.ps1
    write-host "Running SetupAgent Script:"
    . $PSScriptRoot\SetupAgent.ps1
    # Remove users with ADMU_ prefix
    # Remove Created Users
    Get-JCuser -username "ADMU_*" | Remove-JCuser -Force

}

Describe 'Migration Test Scenarios' {
    Context 'Domain Test' {
        # Mock domain
        It 'Test Domain Error'{
            $randomSID = -join ((65..90)  + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            Mock Get-UserHiveFile {$True}
            Mock Get-Domain {$False}
            {Undo-Migration -SelectedUserSID $randomSID} | Should -Throw -expectedMessage "Domain not found"
        }
    }
    #TODO: Function test
    Context 'Reverse Migration Tests Expecting Failures' {
        # Migrate the initialized user to the second username
            It 'Validate NTUser Hive' {
                $Password = "Temp123!"
                $localUser1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                $user1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                # Rename USRClass.DAT
                InitUser -UserName $localUser1 -Password $Password

                Start-Migration -AutobindJCUser $false -JumpCloudUserName $user1 -SelectedUserName "$ENV:COMPUTERNAME\$localUser1" -TempPassword "$($Password)"
                $MigrateUserSID = Get-LocalUser -Name $user1 | Select-Object -ExpandProperty SID

                Rename-Item -Path "C:\Users\$($localUser1)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser1)\AppData\Local\Microsoft\Windows\Test.dat"

                {Undo-Migration -SelectedUserSid $MigrateUserSID} | Should -Throw -expectedMessage "Registry backup file does not exist"

            }
            It 'Validate UsrClass Hive' {
                # Rename USRClass.DAT
                $Password = "Temp123!"
                $localUser2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                $user2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                # Rename USRClass.DAT
                InitUser -UserName $localUser2 -Password $Password
                Start-Migration -AutobindJCUser $false -JumpCloudUserName $user2 -SelectedUserName "$ENV:COMPUTERNAME\$localUser2" -TempPassword "$($Password)"
                $MigrateUserSID = Get-LocalUser -Name $user2 | Select-Object -ExpandProperty SID
                Rename-Item -Path "C:\Users\$($localUser2)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser2)\AppData\Local\Microsoft\Windows\Test.dat"

                {Undo-Migration -SelectedUserSid $MigrateUserSID} | Should -Throw -expectedMessage "Registry backup file does not exist"

            }
            It 'Failure Test using Random SID' {
                $randomSID = -join ((65..90)  + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                {Undo-Migration -SelectedUserSid $randomSID} | Should -Throw
            }
            It 'Test Updated Homepath'{
                BeforeAll{
                    $Password = "Temp123!"
                    $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                    $jcUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                    $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

                    InitUser -UserName $localUser -Password $Password
                        # Start Migration

                    Start-Migration -AutobindJCUser $false -JumpCloudUserName $jcUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)" -UpdateHomePath $true
                    $MigrateUserSID = Get-LocalUser -Name $User| Select-Object -ExpandProperty SID
                }
                It 'Reverse Migrate User with Updated Homepath' {

                    # The HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI should be set to the migrated user
                    Write-Host "##### Reverse Migrate User Test $($migrateUser) #####"
                    # Get local path
                    $updatedHomePath = Get-LocalUser -Name $localUser | Select-Object -ExpandProperty ProfilePath
                    #Check SID
                    {Undo-Migration -SelectedUserSid $MigrateUserSID} | Should -not -Throw

                    $ReverseMigratedUserHomepath = Get-LocalUser -Name $localUser | Select-Object -ExpandProperty ProfilePath
                    $ReverseMigratedUserHomepath | Should -not -Be $updatedHomePath

            }

}
            Context 'Reverse Migration Succesful Test'{
                BeforeAll{
                    $Password = "Temp123!"
                    $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                    $jcUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                    $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                    # Initialize a single user to migrate:

                    InitUser -UserName $localUser -Password $Password
                    # Start Migration

                    Start-Migration -AutobindJCUser $false -JumpCloudUserName $jcUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)"
                    $MigrateUserSID = Get-LocalUser -Name $jcUser | Select-Object -ExpandProperty SID
                }
                It 'Reverse Migrate' {

                    # The HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI should be set to the migrated user
                    Write-Host "##### Reverse Migrate User Test $($migrateUser) #####"
                    #Check SID
                    {Undo-Migration -SelectedUserSid $MigrateUserSID} | Should -not -Throw

                    $ReverseMigratedUser = Get-LocalUser -Name $localUser | Select-Object -ExpandProperty SID
                    $ReverseMigratedUser | Should -not -Be $MigrateUserSID
            }
            }
}
}
AfterAll {
    $systems = Get-JCsdkSystem
    $CIsystems = $systems | Where-Object { $_.displayname -match "packer" }
    foreach ($system in $CIsystems) {
        Remove-JcSdkSystem -id $system.Id
    }
}