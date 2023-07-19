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
    BeforeAll {
        $Password = "Temp123!"
        $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # Initialize a single user to migrate:

        InitUser -UserName $localUser -Password $Password
        # Start Migration
        foreach ($User in $JCReverseMigrateHash.Values) {
            Start-Migration -AutobindJCUser $false -JumpCloudUserName $User.JCUsername -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)"
            $MigrateUserSID = Get-LocalUser -Name $User.JCUsername | Select-Object -ExpandProperty SID
        }

    }
    Context 'Reverse Migration Tests Expecting Failures' {

            # It 'Exit throw for .dat files' {
            #     # Create random profile image path for testing
            #     $randomProfileImagePath = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            #     $randomProfileImagePath2 = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            #     $randomSid = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            #     $randomSID2 = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            #     Update-NTUserDat -CurrentProfileImagePath $randomProfileImagePath -backupProfileImagePath $randomProfileImagePath2 -SelectedUserSid $randomSid -backupProfileImageSid $randomSid2 | Should -Throw

            #     Update-UsrClassDat -CurrentProfileImagePath $randomProfileImagePath -backupProfileImagePath $randomProfileImagePath2 -SelectedUserSid $randomSid -backupProfileImageSid $randomSid2 | Should -Throw
            # }
            # It 'Checks on .dat files SID Test' {
            #     # Create random SID string for testing
            #     $randomSID = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            #     Get-UserHiveFile -SelectedUserSid $randomSID | Should -Throw
            #     Get-UserHiveFile -SelectedUserSid $MigrateUserSID | Should -Not -Throw
            # }

        # Migrate the initialized user to the second username
            It 'Validate NTUser Hive' {
                $Password = "Temp123!"
                $localUser1 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                # Rename USRClass.DAT
                InitUser -UserName $localUser1 -Password $Password
                foreach ($User in $JCReverseMigrateHash.Values) {
                    Start-Migration -AutobindJCUser $false -JumpCloudUserName $User.JCUsername -SelectedUserName "$ENV:COMPUTERNAME\$localUser1" -TempPassword "$($Password)"
                    $MigrateUserSID = Get-LocalUser -Name $User.JCUsername | Select-Object -ExpandProperty SID
                }
                Rename-Item -Path "C:\Users\$($localUser1)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser1)\AppData\Local\Microsoft\Windows\Test.dat"

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw -expectedMessage "Registry backup file does not exist."

            }
            It 'Validate UsrClass Hive' {
                # Rename USRClass.DAT
                $Password = "Temp123!"
                $localUser2 = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                # Rename USRClass.DAT
                InitUser -UserName $localUser2 -Password $Password
                foreach ($User in $JCReverseMigrateHash.Values) {
                    Start-Migration -AutobindJCUser $false -JumpCloudUserName $User.JCUsername -SelectedUserName "$ENV:COMPUTERNAME\$localUser2" -TempPassword "$($Password)"
                    $MigrateUserSID = Get-LocalUser -Name $User.JCUsername | Select-Object -ExpandProperty SID
                }
                Rename-Item -Path "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\Test.dat"

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw -expectedMessage "Registry backup file does not exist."

            }
            It 'Failure Test using Random SID' {
                $randomSID = -join ((65..90)  + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                Reverse-Migration -SelectedUserSid $randomSID | Should -Throw
            }


}


            Context 'Reverse Migration Succesful'{
                It 'Reverse Migrate' {

                    # The HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI should be set to the migrated user
                    Write-Host "##### Reverse Migrate User Test $($migrateUser) #####"
                    #Check SID
                    $MigrateUserSID = Get-LocalUser -Name $migrateUser | Select-Object -ExpandProperty SID
                    Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -not -Throw

                    $ReverseMigratedUser = Get-LocalUser -Name $localUser | Select-Object -ExpandProperty SID
                    $ReverseMigratedUser | Should -not -Be $MigrateUserSID

            }
            }

            Context 'Domain Test' {
                # Mock domain
                $randomSID = -join ((65..90)  + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                It 'Test Domain Error'{
                Mock Get-UserHiveFile {$True}
                Mock Get-Domain {$False}
                {Reverse-Migration -SelectedUserSID $randomSID} | Should -Throw -expectedMessage "Domain not found"
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