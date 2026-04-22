
Describe 'PSScriptAnalyzer Test Suite' -Tag "Module Validation" {
    BeforeAll {
        $ModuleRoot = (Get-Item -Path (Join-Path $PSScriptRoot '../..')).FullName
        $AnalysisPaths = @(
            (Join-Path $ModuleRoot 'Private')
            (Join-Path $ModuleRoot 'Public')
        )
        # Paths to omit from analysis: absolute paths, or paths relative to $ModuleRoot.
        # A path to a directory excludes that directory and all descendants; a file path excludes only that file.
        $PSScriptAnalyzerExcludedPaths = @(
            # e.g. 'Private\SomeFolder\Legacy.ps1'
            # e.g. 'Private\Experimental'
            'Private/WindowsMDM/Get-MdmEnrollmentGuidFromTaskScheduler.ps1'
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
            function Test-PSScriptAnalyzerPathExcluded {
                param(
                    [Parameter(Mandatory)]
                    [string] $CandidatePath,
                    [Parameter(Mandatory)]
                    [string] $ModuleRoot,
                    [string[]] $ExcludedPaths
                )
                if (-not $ExcludedPaths) {
                    return $false
                }
                $normalizedCandidate = [System.IO.Path]::GetFullPath($CandidatePath)
                foreach ($excl in $ExcludedPaths) {
                    if ([string]::IsNullOrWhiteSpace($excl)) {
                        continue
                    }
                    $normalizedExcl = if ([System.IO.Path]::IsPathRooted($excl)) {
                        [System.IO.Path]::GetFullPath($excl)
                    } else {
                        [System.IO.Path]::GetFullPath((Join-Path $ModuleRoot $excl))
                    }
                    if ($normalizedCandidate.Equals($normalizedExcl, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return $true
                    }
                    $directoryPrefix = if ($normalizedExcl.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
                        $normalizedExcl
                    } else {
                        $normalizedExcl + [System.IO.Path]::DirectorySeparatorChar
                    }
                    if ($normalizedCandidate.StartsWith($directoryPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                        return $true
                    }
                }
                return $false
            }

            Write-Host ('[status]Running PSScriptAnalyzer on: ' + ($AnalysisPaths -join ', '))
            if ($PSScriptAnalyzerExcludedPaths) {
                Write-Host ('[status]PSScriptAnalyzer excluded paths: ' + ($PSScriptAnalyzerExcludedPaths -join ', '))
            }
            Write-Host ('[status]PSScriptAnalyzer Settings File: ' + $SettingsFile)
            # Invoke-ScriptAnalyzer -Path is [string] on older PSScriptAnalyzer builds; analyze each root and drop excluded ScriptPath rows.
            $rawScriptAnalyzerResults = foreach ($analysisPath in $AnalysisPaths) {
                if (-not (Test-Path -LiteralPath $analysisPath)) {
                    throw "PSScriptAnalyzer analysis path not found: $analysisPath"
                }
                Invoke-ScriptAnalyzer -Path $analysisPath -Recurse -Settings $settingsObject -ReportSummary
            }
            $ScriptAnalyzerResults = if ($PSScriptAnalyzerExcludedPaths) {
                @($rawScriptAnalyzerResults) | Where-Object {
                    (-not $_.ScriptPath) -or
                    -not (Test-PSScriptAnalyzerPathExcluded -CandidatePath $_.ScriptPath -ModuleRoot $ModuleRoot -ExcludedPaths $PSScriptAnalyzerExcludedPaths)
                }
            } else {
                $rawScriptAnalyzerResults
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