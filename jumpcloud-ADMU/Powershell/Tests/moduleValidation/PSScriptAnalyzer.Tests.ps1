
Describe 'PSScriptAnalyzer Test Suite' -Tag "Module Validation" {
    BeforeAll {
        $ModuleRoot = (Get-Item -Path (Join-Path $PSScriptRoot '../..')).FullName
        $AnalysisPaths = @(
            (Join-Path $ModuleRoot 'Private')
            (Join-Path $ModuleRoot 'Public')
        )
        $SettingsFile = "$PSScriptRoot\PSScriptAnalyzerSettings.psd1"
        # Import Settings:
        $SettingsFromFile = Import-PowerShellDataFile $SettingsFile
        $settingsObject = @{
            Severity     = $SettingsFromFile.Severity
            ExcludeRules = $SettingsFromFile.ExcludeRules
            #IncludeRules = $SettingsFromFile.IncludeRules
            #Rules        = $SettingsFromFile.Rules
        }
    }

    ################################################################################
    # Rules Skipped:
    # 'PSUseShouldProcessForStateChangingFunctions' - #TODO: description
    # 'PSAvoidUsingWriteHost' - Pipeline output
    # 'PSAvoidUsingConvertToSecureStringWithPlainText' - Need to pass to ADMU
    # 'PSAvoidUsingPlainTextForPassword' - Need to pass to ADMU
    # 'PSAvoidUsingUsernameAndPasswordParams' - Need to pass to ADMU
    # 'PSAvoidUsingWMICmdlet' - Needed for several ADMU get info statements
    # 'PSAvoidUsingInvokeExpression' #TODO: Description
    ################################################################################

    Context 'PSScriptAnalyzer Tests' {
        BeforeAll {
            Write-Host ('[status]Running PSScriptAnalyzer on: ' + ($AnalysisPaths -join ', '))
            Write-Host ('[status]PSScriptAnalyzer Settings File: ' + $SettingsFile)
            $rawScriptAnalyzerResults = foreach ($analysisPath in $AnalysisPaths) {
                if (-not (Test-Path -LiteralPath $analysisPath)) {
                    throw "PSScriptAnalyzer analysis path not found: $analysisPath"
                }
                Invoke-ScriptAnalyzer -Path $analysisPath -Recurse -Settings $settingsObject -ReportSummary
            }
            # WindowsMDM/*.ps1 regions are copied from TheJumpCloud/support remove_windowsMDM.ps1 (see Build.Tests.ps1).
            # Skip PSUseOutputTypeCorrectly there so CI stays aligned with upstream without fork churn.
            $windowsMdmSourceRoot = (Get-Item -LiteralPath (Join-Path $ModuleRoot (Join-Path 'Private' 'WindowsMDM'))).FullName
            $ScriptAnalyzerResults = @(
                $rawScriptAnalyzerResults | Where-Object {
                    if ($_.RuleName -ne 'PSUseOutputTypeCorrectly') {
                        return $true
                    }
                    $scriptDir = [System.IO.Path]::GetDirectoryName($_.ScriptPath)
                    if ([string]::IsNullOrEmpty($scriptDir)) {
                        return $true
                    }
                    return -not $scriptDir.StartsWith($windowsMdmSourceRoot, [System.StringComparison]::OrdinalIgnoreCase)
                }
            )
            $suppressedCount = @($rawScriptAnalyzerResults).Count - @($ScriptAnalyzerResults).Count
            if ($suppressedCount -gt 0) {
                Write-Host "[status]Excluded $suppressedCount PSUseOutputTypeCorrectly finding(s) under Private/WindowsMDM (vendored from support repo)."
            }
            if (-not [System.String]::IsNullOrEmpty($ScriptAnalyzerResults)) {
                $ScriptAnalyzerResults | ForEach-Object {
                    Write-Warning ('[PSScriptAnalyzer][' + $_.Severity + '][' + $_.RuleName + '] ' + $_.Message + ' found in "' + $_.ScriptPath + '" at line ' + $_.Line + ':' + $_.Column)
                }
            } else {
                Write-Host ('[success]ScriptAnalyzer returned no results')
            }
        }
        It 'PSScriptAnalyzer Results should be null' {
            $ScriptAnalyzerResults | Should -BeNullOrEmpty
        }
        It 'PSScriptAnalyzer SettingsFile should exist' {
            Test-Path $SettingsFile | Should -Be $true
        }
        It 'PSScriptAnalyzer SettingsObject Should Not Be Null or Empty' {
            $SettingsFromFile | Should -Not -BeNullOrEmpty
            $settingsObject | Should -Not -BeNullOrEmpty
        }

    }
}