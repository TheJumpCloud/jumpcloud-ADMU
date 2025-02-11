Describe "Module Validation Tests" -Tag "Module Validation" {
    BeforeAll {

        if ($env:ModuleVersionType -eq "patch") {
            $env:ModuleVersionType = "build"
        }
        # Get Latest Module Version
        $latestModule = Find-Module -Name JumpCloud.ADMU
        # Import Private Functions:
        $Private = @( Get-ChildItem -Path "$PSScriptRoot/../Private/*.ps1" -Recurse)
        Foreach ($Import in $Private) {
            Try {
                . $Import.FullName
            } Catch {
                Write-Error -Message "Failed to import function $($Import.FullName): $_"
            }
        }
        # Import Public Functions:
        $Private = @( Get-ChildItem -Path "$PSScriptRoot/../Public/*.ps1" -Recurse)
        Foreach ($Import in $Private) {
            Try {
                . $Import.FullName
            } Catch {
                Write-Error -Message "Failed to import function $($Import.FullName): $_"
            }
        }
        # Get PSD1 Version:
        if ($env:ModuleVersionType -eq "manual") {

            $psd1Content = Get-Content -Path "$PSScriptRoot\..\..\JumpCloud.ADMU.psd1"
            $psd1Regex = "ModuleVersion[\s\S]+(([0-9]+)\.([0-9]+)\.([0-9]+))"
            $psd1VersionMatch = Select-String -InputObject:($psd1Content) -Pattern:($psd1Regex)
            $psd1Version = [version]$psd1VersionMatch.Matches.Groups[1].value
            write-host "psd1version $psd1Version"
        }



    }

    Context 'Check Versioning & Signature' {
        # Validate ProgressForm.ps1 ADMU version skip this test
        It 'Progress Form Version' {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $progressFormCmd = Get-Command New-ProgressForm
            $progressFormVersion = $progressFormCmd.Definition | Select-String -Pattern:($VersionRegex)
            $branchProgressFormVersion = [version]$progressFormVersion.Matches.value
            $masterProgressForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Private/DisplayForms/ProgressForm.ps1 -useBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterProgressForm) -Pattern:($VersionRegex)
            $masterProgressFormVersion = [version]$masterVersion.Matches.value
            if ($env:ModuleVersionType -eq "manual") {
                # Manual Versioning
                # Given version should be greater than master
                $branchProgressFormVersion | Should -be $psd1Version
            } else {
                $branchProgressFormVersion | Should -BeGreaterThan $masterProgressFormVersion
                $branchProgressFormVersion.$($env:ModuleVersionType) | Should -Be ($masterProgressFormVersion.$($env:ModuleVersionType) + 1)
            }
        }

        It 'XAML Form version' {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $formCmd = Get-Command Show-SelectionForm
            $formVersion = $formCmd.Definition | Select-String -Pattern:($VersionRegex)
            $branchFormVersion = [version]$formVersion.Matches.value
            $masterForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Private/DisplayForms/Form.ps1 -useBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterForm) -Pattern:($VersionRegex)
            $masterFormVersion = [version]$masterVersion.Matches.value
            if ($env:ModuleVersionType -eq "manual") {
                # Manual Versioning
                # Given version should be greater than master
                $branchFormVersion | Should -be $psd1Version
            } else {
                $branchFormVersion | Should -BeGreaterThan $masterFormVersion
                $branchFormVersion.$($env:ModuleVersionType) | Should -Be ($masterFormVersion.$($env:ModuleVersionType) + 1)
            }

        }

        It 'Start-Migration version' {
            $VersionRegex = [regex]"(?<=admuVersion = ')(([0-9]+)\.([0-9]+)\.([0-9]+))"
            $startMigrationCmd = Get-Command Start-Migration
            $admuVersion = $startMigrationCmd.Definition | Select-String -Pattern:($VersionRegex)
            $branchStartMigrationVersion = [version]$admuVersion.Matches.value
            $masterStartMigration = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Public/Start-Migration.ps1 -useBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterStartMigration) -Pattern:($VersionRegex)
            $masterStartMigrationVersion = [version]$masterVersion.Matches.value
            if ($env:ModuleVersionType -eq "manual") {
                $branchStartMigrationVersion | Should -be $psd1Version
            } else {
                $branchStartMigrationVersion | Should -BeGreaterThan $masterStartMigrationVersion
                $branchStartMigrationVersion.$($env:ModuleVersionType) | Should -Be ($masterStartMigrationVersion.$($env:ModuleVersionType) + 1)
            }
        }

        It 'gui_jcadmu.exe/ uwp_jcadmu.exe versions' {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $masterForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Private/DisplayForms/Form.ps1 -useBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterForm) -Pattern:($VersionRegex)
            $masterFormVersion = [version]$masterVersion.Matches.value
            $gui_exePathFromArtifact = "$PSScriptRoot\..\..\..\Exe\gui_jcadmu.exe"
            $uwp_exePathFromArtifact = "$PSScriptRoot\..\..\..\Exe\uwp_jcadmu.exe"
            $gui_exeVersion = [version](Get-Item ("$gui_exePathFromArtifact")).VersionInfo.FileVersion
            $wup_exeVersion = [version](Get-Item ("$uwp_exePathFromArtifact")).VersionInfo.FileVersion
            if ($env:ModuleVersionType -eq "manual") {
                $gui_exeVersion | Should -be $psd1Version
                $wup_exeVersion | Should -be $psd1Version
            } else {
                $gui_exeVersion | Should -BeGreaterThan $masterFormVersion
                $gui_exeVersion.$($env:ModuleVersionType) | Should -Be ($masterFormVersion.$($env:ModuleVersionType) + 1)
                $wup_exeVersion | Should -BeGreaterThan $masterFormVersion
                $wup_exeVersion.$($env:ModuleVersionType) | Should -Be ($masterFormVersion.$($env:ModuleVersionType) + 1)
            }
        }
    }

    Context 'Module Changelog Validation' {
        BeforeAll {
            # Get ModuleChangelog.md Version:
            $FilePath_ModuleChangelog = "$PSScriptRoot\..\..\..\ModuleChangelog.md"
            $ModuleChangelogContent = Get-Content -Path:($FilePath_ModuleChangelog)

        }
        It 'Module ChangLog Version should be correct' {
            $ModuleChangelogVersionRegex = "([0-9]+)\.([0-9]+)\.([0-9]+)"
            $ModuleChangelogVersionMatch = ($ModuleChangelogContent | Select-Object -First 1) | Select-String -Pattern:($ModuleChangelogVersionRegex)
            Write-Host "Module Changelog Content: $ModuleChangelogVersionMatch"
            $ModuleChangelogVersion = $ModuleChangelogVersionMatch.Matches.Value
            Write-Host "Module Changelog Version: $ModuleChangelogVersion"
            $latestVersion = [version]$latestModule.version
            if ($env:ModuleVersionType -eq "manual") {
                $ModuleChangelogVersion | Should -be $psd1Version
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
                Write-Host "Validating documentation for doc file: $($item)"
                $diff = git diff -- $item.fullname
                if ($diff) {
                    write-warning "diff found in file: $($item.fullname) when we expected none to exist; have you run build.ps1 and committed the resulting changes?"
                }
                $diff | Should -BeNullOrEmpty
            }
        }
    }
}