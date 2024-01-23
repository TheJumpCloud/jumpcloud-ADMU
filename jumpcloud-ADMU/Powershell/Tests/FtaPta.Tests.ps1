# Create test for CSV file creation
# Create test for Setting the FTA
# Create test for Setting the PTA

function Enable-TestNameAsVariablePlugin {
    & (get-module pester) {
        $PluginParams = @{
            Name               = "SaveTestNameToVariable"
            EachTestSetupStart = {
                $GLOBAL:TestName = $Context.Test.Name
            }
            EachTestTeardown   = {
                $GLOBAL:TestName = $null
            }
        }
        $state.Plugin += New-PluginObject @PluginParams
    }
}
BeforeAll {
    # import build variables for test cases
    write-host "Importing Build Variables:"
    . $PSScriptRoot\BuildVariables.ps1
    # import functions from start migration
    write-host "Importing Start-Migration Script:"
    . $PSScriptRoot\..\Start-Migration.ps1
    # setup tests (This creates any of the users in the build vars dictionary)
    write-host "Running SetupAgent Script:"
    . $PSScriptRoot\SetupAgent.ps1
}

# Describe to check for CSV file creation
Describe 'Set-FTA/PTA Test Scenarios'{
    Enable-TestNameAsVariablePlugin
    BeforeEach {
        Write-Host "---------------------------"
        Write-Host "Begin Test: $testName`n"
    }

    Context 'FTA and PTA CSV creation test'{

        $Password = "Temp123!"
        $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
        # Initialize a single user to migrate:
        InitUser -UserName $localUser -Password $Password

        Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)" -SetDefaultWindowsUser $true

        # Check if Users/User/AppData/Local/JUMPCLOUDADMU/FTA.csv exists
        It "fta_manifest.csv should exist" {
            $FTAPath = "C:\Users\$($localUser)\AppData\Local\JumpCloudADMU\fta_manifest.csv"
            # Check if it contains data
            $FTAData = Import-Csv $FTAPath
            $FTAData | Should -Not -BeNullOrEmpty
        }
        It "pta_manifest.csv should exist" {
            $PTAPath = "C:\Users\$($localUser)\AppData\Local\JumpCloudADMU\pta_manifest.csv"
            # Check if it contains data
            $PTAData = Import-Csv $PTAPath
            $PTAData | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Set-FTA Test'{
        BeforeAll{
            # Import /Deploy/uwp_jcadmu.ps1 and use the function Set-FTA
            . $PSScriptRoot\..\Deploy\uwp_jcadmu.ps1
        }
        It 'Set-FTA should be changed after migration'{
            # Change the FTA for .txt files to wordpad

            Set-FTA "C:\Program Files\Windows NT\Accessories\wordpad.exe" .txt
            $Password = "Temp123!"
            $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $localUser -Password $Password

            Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)" -SetDefaultWindowsUser $true

            $program =  Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$extension\UserChoice"
            # Check if programId is wordpad
            $program.ProgId | Should -Match "wordpad"

        }
    }

    Context 'Set-PTA Test'{
        BeforeAll{
            # Import /Deploy/uwp_jcadmu.ps1 and use the function Set-FTA
            . $PSScriptRoot\..\Deploy\uwp_jcadmu.ps1
        }
        It 'Set-PTA should be changed after migration'{
            # Change the PTA for .txt files to wordpad
            $protocol = "http"
            Set-PTA -Protocol $protocol -ProgId "notepad"
            $Password = "Temp123!"
            $localUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            $migrateUser = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # Initialize a single user to migrate:
            InitUser -UserName $localUser -Password $Password

            Start-Migration -AutobindJCUser $false -JumpCloudUserName $migrateUser -SelectedUserName "$ENV:COMPUTERNAME\$localUser" -TempPassword "$($Password)" -SetDefaultWindowsUser $true

            $program =  Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($protocol)\UserChoice"
            # Check if programId is notepad
            $program.ProgId | Should -Match "notepad"
        }
    }

}