BeforeAll {
    # import functions from start migration
    write-host "Importing Reverse-Migrate Script:"
    . $PSScriptRoot\..\Reverse-Migrate.ps1
    . $PSScriptRoot\..\Start-Migration.ps1
    # Remove users with ADMU_ prefix
    # Remove Created Users
    Get-JCuser -username "ADMU_*" | Remove-JCuser -Force
}

Describe 'Migration Test Scenarios' {
    Context 'Reverse Migration Tests' {
            $Password = "Temp123!"
            $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $localUser -Password $Password


            # Migrate the initialized user to the second username
            Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)"
            $MigrateUserSID = Get-LocalUser -Name $migrateUser | Select-Object -ExpandProperty SID
        # TODO: Checks on .dat files
            # TODO: Failure Test
            # TODO: exit throw for .dat files
            #TODO: Load test should throw if already loaded
            #TODO: Mock domain


            It 'Exit throw for .dat files' {
                # Create random profile image path for testing
                $randomProfileImagePath = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                $randomProfileImagePath2 = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                $randomSid = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                $randomSID2 = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

                Update-NTUserDat -CurrentProfileImagePath $randomProfileImagePath -backupProfileImagePath $randomProfileImagePath2 -SelectedUserSid $randomSid -backupProfileImageSid $randomSid2 | Should -Throw

                Update-UsrClassDat -CurrentProfileImagePath $randomProfileImagePath -backupProfileImagePath $randomProfileImagePath2 -SelectedUserSid $randomSid -backupProfileImageSid $randomSid2 | Should -Throw
            }
            It 'Checks on .dat files SID Test' {
                # Create random SID string for testing
                $randomSID = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                Validate-ProfileRegistryPath -SelectedUserSid $randomSID | Should -Throw

                Validate-ProfileRegistryPath -SelectedUserSid $MigrateUserSID | Should -Not -Throw

            }
            It 'Validate NTUser Hive' {
                mock Get-UserHiveFile {true}
                # Rename USRClass.DAT
                Rename-Item -Path "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\Test.dat"

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw
            }
            It 'Validate UsrClass Hive' {
                mock Get-UserHiveFile {true}
                # Rename USRClass.DAT
                Rename-Item -Path "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\Test.dat"

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw
            }


            It 'Load test should throw if already loaded' {
            }
            It 'Mock domain' {
            }
            It 'Failure Test' {
                $randomSID = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                Reverse-Migration -SelectedUserSid $randomSID | Should -Throw

                # Mock rename of NTUser.dat
                mock Rename-Item {true}

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw
            }
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
}
AfterAll {
    $systems = Get-JCsdkSystem
    $CIsystems = $systems | Where-Object { $_.displayname -match "packer" }
    foreach ($system in $CIsystems) {
        Remove-JcSdkSystem -id $system.Id
    }
}