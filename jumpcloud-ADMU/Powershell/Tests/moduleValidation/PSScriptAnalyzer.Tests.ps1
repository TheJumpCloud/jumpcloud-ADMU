
Describe 'PSScriptAnalyzer Test Suite' -Tag "Module Validation" {
    BeforeAll {
        $FolderPath_Module = (Get-Item -Path("$PSScriptRoot/../../")).FullName
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
            Write-Host ('[status]Running PSScriptAnalyzer on: ' + $FolderPath_Module)
            Write-Host ('[status]PSScriptAnalyzer Settings File: ' + $SettingsFile)
            $ScriptAnalyzerResults = Invoke-ScriptAnalyzer -Path:($FolderPath_Module) -Recurse -Settings $settingsObject -ReportSummary
            if (-not [System.String]::IsNullOrEmpty($ScriptAnalyzerResults)) {
                $ScriptAnalyzerResults | ForEach-Object {
                    Write-Error ('[PSScriptAnalyzer][' + $_.Severity + '][' + $_.RuleName + '] ' + $_.Message + ' found in "' + $_.ScriptPath + '" at line ' + $_.Line + ':' + $_.Column)
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