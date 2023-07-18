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
        foreach
        Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)"
        $MigrateUserSID = Get-LocalUser -Name $migrateUser | Select-Object -ExpandProperty SID
    }
    Context 'Reverse Migration Tests Expecting Failures' {
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
                Get-UserHiveFile -SelectedUserSid $randomSID | Should -Throw
                Get-UserHiveFile -SelectedUserSid $MigrateUserSID | Should -Not -Throw

            }
            It 'Validate NTUser Hive' {
                # Rename USRClass.DAT
                Rename-Item -Path "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\Test.dat"

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw -expectedMessage "Registry backup file does not exist."
            }
            It 'Validate UsrClass Hive' {
                mock Get-UserHiveFile {$true}
                # Rename USRClass.DAT
                Rename-Item -Path "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "C:\Users\$($localUser)\AppData\Local\Microsoft\Windows\Test.dat"

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw -expectedMessage "Registry backup file does not exist."

            }


            It 'Load test should throw if already loaded' {
            }
            It 'Mock domain' {
                $domainController = New-MockObject -Type 'Microsoft.ActiveDirectory.Management.ADComputer' -MemberData @{
                    Name = 'Test Mock Domain'
                    DNSHostName = 'dc01.example.com'
                    OperatingSystem = 'Windows Server 2019'
                }
                $domainController | Should -BeOfType 'Microsoft.ActiveDirectory.Management.ADComputer'

                Get-Domain | Should -Be $false
            }
            It 'Failure Test' {
                $randomSID = -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
                Reverse-Migration -SelectedUserSid $randomSID | Should -Throw

                # Mock rename of NTUser.dat
                mock Rename-Item {true}

                Reverse-Migration -SelectedUserSid $MigrateUserSID | Should -Throw
            }


}

}
Context 'Reverse Migration Succesfull'{
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

	It 'Test Domain Error'{
	Mock Get-UserHiveFile {$True}
    Mock Get-Domain {$False}
    {Reverse-Migration -SelectedUserSID adasasasdasdasd123dsa} | Should -Throw -expectedMessage "Domain not found"
}

    }
AfterAll {
    $systems = Get-JCsdkSystem
    $CIsystems = $systems | Where-Object { $_.displayname -match "packer" }
    foreach ($system in $CIsystems) {
        Remove-JcSdkSystem -id $system.Id
    }
}