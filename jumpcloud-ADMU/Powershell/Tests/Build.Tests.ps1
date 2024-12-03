Describe "Module Validation Tests" {
    BeforeAll {
        Write-Host "Script Location: $PSScriptRoot"
        # translate $ModuleVersionType for [version] string matching module
        if ($env:ModuleVersionType -eq "patch") {
            $env:ModuleVersionType = "build"
        }
        # Get Latest Module Version
        $lastestModule = Find-Module -Name JumpCloud.ADMU

    }
    Describe 'Build EXE Tests' {

        Context 'Validate EXE Files Exist and were re-generated' {

            It 'gui_jcadmu.exe exists and was generated today' {
                $guiPath = ("$PSScriptRoot\..\..\Exe\gui_jcadmu.exe")
                (Test-Path -Path $guiPath) | Should -Be $true
                $binaryFile = Get-ChildItem -Path $guiPath
                [datetime]$binaryFile.LastWriteTime | Should -BeGreaterThan (Get-Date -Format "dddd MM/dd/yyyy")
            }
            It 'uwp_jcadmu.exe exists and was generated today' {
                $uwpPath = ("$PSScriptRoot\..\..\Exe\uwp_jcadmu.exe")
                (Test-Path -Path $uwpPath) | Should -Be $true
                $binaryFile = Get-ChildItem -Path $uwpPath
                [datetime]$binaryFile.LastWriteTime | Should -BeGreaterThan (Get-Date -Format "dddd MM/dd/yyyy")
            }
        } -Skip
    }

    Context 'Check Versioning & Signature' {
        # Validate ProgressForm.ps1 ADMU version skip this test
        It 'Progress Form Version' {
            $ProgressFormPath = "$PSScriptRoot\..\ProgressForm.ps1"
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $progressformversion = Select-String -Path:($ProgressFormPath) -Pattern:($VersionRegex)
            $branchprogressformversion = [version]$progressformversion.Matches.value
            $masterProgressForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/ProgressForm.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterProgressForm) -Pattern:($VersionRegex)
            $masterprogressformversion = [version]$masterversion.Matches.value
            if($env:ModuleVersionType -eq "manual"){
                # Manual Versioning
                # Given version should be greater than master
                $branchprogressformversion | Should -BeGreaterThan $masterprogressformversion
            } else {
                $branchprogressformversion | Should -BeGreaterThan $masterprogressformversion
                $branchprogressformversion.$($env:ModuleVersionType) | Should -Be ($masterprogressformversion.$($env:ModuleVersionType) + 1)
            }
        } -Skip

        It 'XAML Form version' {
            $FormPath = "$PSScriptRoot\..\Form.ps1"
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $formversion = Select-String -Path:($formpath) -Pattern:($VersionRegex)
            $branchformversion = [version]$formversion.Matches.value
            $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Form.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
            $masterformversion = [version]$masterversion.Matches.value
            if($env:ModuleVersionType -eq "manual"){
                # Manual Versioning
                # Given version should be greater than master
                $branchformversion | Should -BeGreaterThan $masterformversion
            } else {
                $branchformversion | Should -BeGreaterThan $masterformversion
                $branchformversion.$($env:ModuleVersionType) | Should -Be ($masterformversion.$($env:ModuleVersionType) + 1)
            }

        }

        It 'Start-Migration version' {
            $startMigrationPath = "$PSScriptRoot\..\Start-Migration.ps1"
            $VersionRegex = [regex]"(?<=admuVersion = ')(([0-9]+)\.([0-9]+)\.([0-9]+))"
            $admuversion = Select-String -Path:($startMigrationPath) -Pattern:($VersionRegex)
            $branchStartMigrationVersion = [version]$admuversion.Matches.value
            $masterStartMigration = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Start-Migration.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterStartMigration) -Pattern:($VersionRegex)
            $masterStartMigrationVersion = [version]$masterVersion.Matches.value
            if ($env:ModuleVersionType -eq "manual") {
                $branchStartMigrationVersion | Should -BeGreaterThan $masterStartMigrationVersion
            } else {
                $branchStartMigrationVersion | Should -BeGreaterThan $masterStartMigrationVersion
                $branchStartMigrationVersion.$($env:ModuleVersionType) | Should -Be ($masterStartMigrationVersion.$($env:ModuleVersionType) + 1)
            }
        }

        It 'gui_jcadmu.exe version' -skip {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Form.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
            $masterformversion = [version]$masterversion.Matches.value
            $exeversion = [version](Get-Item ("$PSScriptRoot\..\..\exe\gui_jcadmu.exe")).VersionInfo.FileVersion
            if ($env:ModuleVersionType -eq "manual") {
                $exeversion | Should -BeGreaterThan $masterformversion
            } else {
                $exeversion | Should -BeGreaterThan $masterformversion
                $exeversion.$($env:ModuleVersionType) | Should -Be ($masterformversion.$($env:ModuleVersionType) + 1)
            }
        }
    }

    Context 'Module Changelog Validation' {
        BeforeAll {
            # Get ModuleChangelog.md Version:
            $FilePath_ModuleChangelog = "$PSScriptRoot\..\..\..\ModuleChangelog.md"
            $ModuleChangelogContent = Get-Content -Path:($FilePath_ModuleChangelog)

        }
        It 'Module Changlog Version should be correct' {
            $ModuleChangelogVersionRegex = "([0-9]+)\.([0-9]+)\.([0-9]+)"
            $ModuleChangelogVersionMatch = ($ModuleChangelogContent | Select-Object -First 1) | Select-String -Pattern:($ModuleChangelogVersionRegex)
            Write-Host "Module Changelog Content: $ModuleChangelogVersionMatch"
            $ModuleChangelogVersion = $ModuleChangelogVersionMatch.Matches.Value
            Write-Host "Module Changelog Version: $ModuleChangelogVersion"
            $latestVersion = [version]$lastestModule.version
            if ($env:ModuleVersionType -eq "manual") {
                $ModuleChangelogVersion | Should -BeGreaterThan $latestVersion
            } else {
                ([version]$ModuleChangelogVersion).$($env:ModuleVersionType) | Should -Be ($latestVersion.$($env:ModuleVersionType) + 1)
            }

        }
        It 'Module Changelog should not contain placeholder values' {
            $ModuleChangelogContent | Should -not -Match "{{Fill in the"
        }
    }

    Context 'Module Help Files' {
        It 'Validates no new changes should be committed after running Build.ps1' {
            # Get Docs Directory:
            $FolderPath_Docs = "$PSScriptRoot\..\..\Docs\"
            $Docs = Get-ChildItem -Path $FolderPath_Docs -Filter "*.md"
            Write-Host $Docs
            foreach ($item in $Docs) {
                Write-Host "testing ::::: $($item)"
                $diff = git diff -- $item.fullname
                if ($diff) {
                    write-warning "diff found in file: $($item.fullname) when we expected none to exist; have you run build.ps1 and committed the resulting changes?"
                }
                $diff | Should -BeNullOrEmpty
            }
        }
    }
}