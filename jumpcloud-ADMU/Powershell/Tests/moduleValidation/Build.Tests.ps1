Describe "Module Validation Tests" -Tag "Module Validation" {
    BeforeAll {
        $env:ModuleVersionType = $env:RELEASE_TYPE
        if ($env:ModuleVersionType -eq "patch") {
            $env:ModuleVersionType = "build"
        }
        # Get Latest Module Version
        $latestModule = Find-Module -Name JumpCloud.ADMU
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
        # Get PSD1 Version:
        $psd1Path = Join-Path "$PSScriptRoot" "\..\..\..\JumpCloud.ADMU.psd1"
        if ($env:ModuleVersionType -eq "manual") {
            $psd1Content = Get-Content -Path $psd1Path
            $psd1Regex = "ModuleVersion[\s\S]+(([0-9]+)\.([0-9]+)\.([0-9]+))"
            $psd1VersionMatch = Select-String -InputObject:($psd1Content) -Pattern:($psd1Regex)
            $psd1Version = [version]$psd1VersionMatch.Matches.Groups[1].value
            Write-Host "psd1version $psd1Version"
        }
    }

    Context 'Check Versioning & Signature' {
        # Validate ProgressForm.ps1 ADMU version skip this test
        It 'Progress Form Version' {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $progressFormCmd = Get-Command New-ProgressForm
            $progressFormVersion = $progressFormCmd.Definition | Select-String -Pattern:($VersionRegex)
            $branchProgressFormVersion = [version]$progressFormVersion.Matches.value
            $masterProgressForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Private/DisplayForms/ProgressForm.ps1 -UseBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterProgressForm) -Pattern:($VersionRegex)
            $masterProgressFormVersion = [version]$masterVersion.Matches.value
            if ($env:ModuleVersionType -eq "manual") {
                # Manual Versioning
                # Given version should be greater than master
                $branchProgressFormVersion | Should -Be $psd1Version
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
            $masterForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Private/DisplayForms/Form.ps1 -UseBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterForm) -Pattern:($VersionRegex)
            $masterFormVersion = [version]$masterVersion.Matches.value
            if ($env:ModuleVersionType -eq "manual") {
                # Manual Versioning
                # Given version should be greater than master
                $branchFormVersion | Should -Be $psd1Version
            } else {
                $branchFormVersion | Should -BeGreaterThan $masterFormVersion
                $branchFormVersion.$($env:ModuleVersionType) | Should -Be ($masterFormVersion.$($env:ModuleVersionType) + 1)
            }

        }

        It 'Start-Migration version' {
            $VersionRegex = [regex]'\$admuVersion\s=\s\"([0-9]+.[0-9]+.[0-9]+)\"'
            $startMigrationCmd = Get-Command Start-Migration
            $admuVersionRaw = $startMigrationCmd.Definition | Select-String -Pattern:($VersionRegex)
            $admuVersion = $admuVersionRaw.matches.groups[1].value
            $branchStartMigrationVersion = [version]$admuVersion
            $masterStartMigration = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Public/Start-Migration.ps1 -UseBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterStartMigration) -Pattern:($VersionRegex)
            Write-Host "Master Version Raw: $($masterVersion.matches.groups[1].value)"
            $masterStartMigrationVersion = [version]$masterVersion.matches.groups[1].value
            if ($env:ModuleVersionType -eq "manual") {
                $branchStartMigrationVersion | Should -Be $psd1Version
            } else {
                $branchStartMigrationVersion | Should -BeGreaterThan $masterStartMigrationVersion
                Write-Host "Branch Start-Migration Version: $branchStartMigrationVersion"
                Write-Host "Master Start-Migration Version: $masterStartMigrationVersion"
                $branchStartMigrationVersion.$($env:ModuleVersionType) | Should -Be ($masterStartMigrationVersion.$($env:ModuleVersionType) + 1)
            }
        }

        It 'gui_jcadmu.exe/ uwp_jcadmu.exe versions' {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )([0-9]+)\.([0-9]+)\.([0-9]+)'
            $masterForm = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Private/DisplayForms/Form.ps1 -UseBasicParsing).ToString()
            $masterVersion = Select-String -InputObject:($masterForm) -Pattern:($VersionRegex)
            $masterFormVersion = [version]$masterVersion.Matches.value
            $gui_exePathFromArtifact = "$PSScriptRoot\..\..\..\Exe\gui_jcadmu.exe"
            $uwp_exePathFromArtifact = "$PSScriptRoot\..\..\..\Exe\uwp_jcadmu.exe"
            $gui_exeVersion = [version](Get-Item ("$gui_exePathFromArtifact")).VersionInfo.FileVersion
            $wup_exeVersion = [version](Get-Item ("$uwp_exePathFromArtifact")).VersionInfo.FileVersion
            if ($env:ModuleVersionType -eq "manual") {
                $gui_exeVersion | Should -Be $psd1Version
                $wup_exeVersion | Should -Be $psd1Version
            } else {
                $gui_exeVersion | Should -BeGreaterThan $masterFormVersion
                $gui_exeVersion.$($env:ModuleVersionType) | Should -Be ($masterFormVersion.$($env:ModuleVersionType) + 1)
                $wup_exeVersion | Should -BeGreaterThan $masterFormVersion
                $wup_exeVersion.$($env:ModuleVersionType) | Should -Be ($masterFormVersion.$($env:ModuleVersionType) + 1)
            }
        }
    }

    Context "Module PSD1 Validation" {
        # Validate PSD1 version matches the module version
        It 'Validates the encoding of the PSD1 file' {
            function Get-FileEncoding {
                param(
                    [string]$Path
                )
                $encoding = [System.Text.Encoding]::Default
                $buffer = New-Object byte[] 4
                $fileStream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
                $fileStream.Read($buffer, 0, 4)
                $fileStream.Close()
                if ($buffer[0] -eq 0xef -and $buffer[1] -eq 0xbb -and $buffer[2] -eq 0xbf) {
                    $encoding = [System.Text.Encoding]::UTF8
                } elseif ($buffer[0] -eq 0xfe -and $buffer[1] -eq 0xff) {
                    $encoding = [System.Text.Encoding]::BigEndianUnicode
                } elseif ($buffer[0] -eq 0xff -and $buffer[1] -eq 0xfe) {
                    $encoding = [System.Text.Encoding]::Unicode
                } elseif ($buffer[0] -eq 0x00 -and $buffer[1] -eq 0x00 -and $buffer[2] -eq 0xfe -and $buffer[3] -eq 0xff) {
                    $encoding = [System.Text.Encoding]::UTF32
                }
                return $encoding
            }

            $psd1Path = Join-Path $PSScriptRoot "\..\..\..\JumpCloud.ADMU.psd1"
            $encoding = (Get-FileEncoding -Path $psd1Path)[1]
            Write-Host "Encoding: $($encoding.BodyName)"
            $encoding.BodyName | Should -BeIn @('utf-8', 'utf-16')
        }
        It 'PSD1 version' {
            $psd1Content = Get-Content -Path $psd1Path
            $psd1Regex = "ModuleVersion[\s\S]+(([0-9]+)\.([0-9]+)\.([0-9]+))"
            $psd1VersionMatch = Select-String -InputObject:($psd1Content) -Pattern:($psd1Regex)
            $psd1Version = [version]$psd1VersionMatch.Matches.Groups[1].value
            if ($env:ModuleVersionType -eq "manual") {
                # Manual Versioning
                # Given version should be greater than master
                $psd1Version | Should -BeGreaterThan $latestModule.Version
            } else {
                $psd1Version | Should -BeGreaterThan $latestModule.Version
                $psd1Version.$($env:ModuleVersionType) | Should -Be (([version]$($latestModule.Version)).$env:ModuleVersionType + 1)
            }
        }
        It 'The date on the current version of the Module Manifest file should be todays date' {
            # get content from current path
            $moduleContent = Get-Content -Path ("$psd1Path")
            # update module manifest
            Update-ModuleManifest -Path:($psd1Path)
            $stringMatch = Select-String -InputObject $moduleContent -Pattern "# Generated on: ([\d]+\/[\d]+\/[\d]+)"
            $PSD1_date = $stringMatch.matches.groups[1].value
            ([datetime]$PSD1_date) | Should -Be ([datetime]( Get-Date -Format "M/d/yyyy" ))
        }
    }

    Context "admuTemplate Validation" -Skip {
        It "admuTemplate should have been generated" {
            $admuTemplatePath = Join-Path $Global:rootModule "Deploy\admuTemplate.ps1"
            $admuTemplatePath | Should -Exist
        }
    }

    Context 'Module Changelog Validation' {
        BeforeAll {
            # Get ModuleChangelog.md Version:
            $FilePath_ModuleChangelog = "$PSScriptRoot\..\..\..\..\ModuleChangelog.md"
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
                $ModuleChangelogVersion | Should -Be $psd1Version
            } else {
                ([version]$ModuleChangelogVersion).$($env:ModuleVersionType) | Should -Be ($latestVersion.$($env:ModuleVersionType) + 1)
            }

        }
        It 'Module Changelog should not contain placeholder values' {
            $ModuleChangelogContent | Should -Not -Match "{ { Fill in the"
        }
        It 'Module Changelog Version should be todays date' {
            $moduleChangelogContent = Get-Content ("$FilePath_ModuleChangelog") -TotalCount 3

            # latest from changelog
            $stringMatch = Select-String -InputObject $moduleChangelogContent -Pattern "## ([0-9]+.[0-9]+.[0-9]+)"
            $latestChangelogVersion = $stringMatch.matches.groups[1].value
            $stringMatch = Select-String -InputObject $moduleChangelogContent -Pattern "Release Date: (.*)"
            $latestReleaseDate = $stringMatch.matches.groups[1].value.trim(" ")
            switch ($env:ModuleVersionType) {
                'major' {
                    $versionString = "$($(([version]$latestModule.Version).Major) + 1).0.0"
                    Write-Host "[Module Validation Tests] Development Version Major Changelog Version: $($latestChangelogVersion) Should be $versionString"
                    ([Version]$latestChangelogVersion).Major | Should -Be (([version]$latestModule.Version).Major + 1)
                    ([Version]$latestChangelogVersion) | Should -BeGreaterThan (([version]$latestModule.Version))
                }
                'minor' {
                    $versionString = "$($(([version]$latestModule.Version).Major)).$(([version]$latestModule.Version).minor + 1).0"
                    Write-Host "[Module Validation Tests] Development Version Minor Changelog Version: $($latestChangelogVersion) Should be $versionString"
                    ([Version]$latestChangelogVersion).Minor | Should -Be (([version]$latestModule.Version).Minor + 1)
                    ([Version]$latestChangelogVersion) | Should -BeGreaterThan (([version]$latestModule.Version))
                }
                'patch' {
                    $versionString = "$($(([version]$latestModule.Version).Major)).$(([version]$latestModule.Version).minor).$(([version]$latestModule.Version).Build + 1)"
                    Write-Host "[Module Validation Tests] Development Version Build Changelog Version: $($latestChangelogVersion) Should be $versionString"
                    ([Version]$latestChangelogVersion).Build | Should -Be (([version]$latestModule.Version).Build + 1)
                    ([Version]$latestChangelogVersion) | Should -BeGreaterThan (([version]$latestModule.Version))
                }
                'manual' {
                    Write-Host "[Module Validation Tests] Development Version Changelog Version: $($latestChangelogVersion) is going to be manually released to PowerShell Gallery"
                    ([Version]$latestChangelogVersion) | Should -BeGreaterThan (([version]$latestModule.Version))
                }
            }
            $todayDate = Get-Date -UFormat "%B %d, %Y"
            if ($todayDate | Select-String -Pattern "0\d,") {
                $todayDate = "$(Get-Date -UFormat %B) $($(Get-Date -UFormat %d) -replace '0', ''), $(Get-Date -UFormat %Y)"
            }
            $latestReleaseDate | Should -Be $todayDate
        }
    }

    Context 'Windows MDM Function Sync' {
        BeforeAll {
            # Module root is 3 levels up from Tests/moduleValidation
            $moduleBase = $PSScriptRoot
            1..3 | ForEach-Object { $moduleBase = Split-Path $moduleBase -Parent }
            $scriptUrl = 'https://raw.githubusercontent.com/TheJumpCloud/support/master/scripts/windows/remove_windowsMDM.ps1'
            $supportScriptContent = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing -ErrorAction Stop | Select-Object -ExpandProperty Content
            $windowsMdmRegionNames = @('Get-MdmEnrollmentGuidFromTaskScheduler', 'Get-WindowsMDMProvider', 'Remove-WindowsMDMProvider')

            function Get-NormalizedFunctionContent {
                param([string]$Content)
                if (-not $Content) { return '' }
                $trimmed = $Content.Trim()
                $normalized = ($trimmed -replace "`r`n", "`n") -replace "`r", "`n"
                return $normalized.Trim()
            }

            function Get-SupportScriptRegionContent {
                param([string]$ScriptContent, [string]$RegionName)
                $startPattern = [regex]::Escape("#startregion $RegionName")
                $endPattern = [regex]::Escape("#endregion $RegionName")
                $pattern = "(?s)${startPattern}\s*(.*?)${endPattern}"
                $m = [regex]::Match($ScriptContent, $pattern)
                if (-not $m.Success) { return $null }
                return $m.Groups[1].Value
            }
        }

        It 'Windows MDM function definitions match remove_windowsMDM.ps1 on support repo' {
            $failures = [System.Collections.ArrayList]::new()
            foreach ($regionName in $windowsMdmRegionNames) {
                $localPath = Join-Path $moduleBase 'Powershell' 'Private' 'WindowsMDM' "$regionName.ps1"
                if (-not (Test-Path $localPath)) {
                    [void]$failures.Add("Local file not found: $localPath")
                    continue
                }
                $regionContent = Get-SupportScriptRegionContent -ScriptContent $supportScriptContent -RegionName $regionName
                if ($null -eq $regionContent) {
                    [void]$failures.Add("The script at $scriptUrl does not define the required region '#region $regionName ... #endregion $regionName'. Please add this region to the script.")
                    continue
                }
                $localContent = Get-Content -Path $localPath -Raw -ErrorAction Stop
                $normalizedRegion = Get-NormalizedFunctionContent $regionContent
                $normalizedLocal = Get-NormalizedFunctionContent $localContent
                if ($normalizedRegion -ne $normalizedLocal) {
                    [void]$failures.Add("The function definition for '$regionName' does not match the script's definition. Please update jumpcloud-ADMU/Powershell/Private/WindowsMDM/$regionName.ps1 from the script at $scriptUrl (region: #region $regionName ... #endregion $regionName).")
                }
            }
            $failures.Count | Should -Be 0 -Because ($failures -join ' ')
        }
    }

    Context 'Module Help Files' {
        It 'Validates no new changes should be committed after running Build.ps1' {
            # Get Docs Directory:
            $FolderPath_Docs = "$PSScriptRoot\..\..\..\Docs\"
            $Docs = Get-ChildItem -Path $FolderPath_Docs -Filter "*.md"
            Write-Host $Docs
            foreach ($item in $Docs) {
                Write-Host "Validating documentation for doc file: $($item)"
                # Use git diff with --ignore-cr-at-eol to ignore line ending differences to account for docs being generated on different OSes
                $diff = git diff --ignore-cr-at-eol -- $item.fullname
                if ($diff) {
                    Write-Warning "Diff found in file: $($item.fullname) when we expected none to exist; have you run build.ps1 and committed the resulting changes?"
                    Write-Warning "Diff output: $diff"
                }
                $diff | Should -BeNullOrEmpty
            }
        }
    }
}