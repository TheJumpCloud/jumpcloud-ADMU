$FolderPath_Module = (Get-Item -Path($PSScriptRoot)).Parent.FullName
$SettingsFile = "/Users/jworkman/Documents/GitHub/jumpcloud-ADMU/jumpcloud-ADMU/Powershell/Tests/PSScriptAnalyzerSettings.psd1"
# Import Settings:
$SettingsFromFile = Import-PowerShellDataFile $SettingsFile
$settingsObject = @{
    Severity = $SettingsFromFile.Severity
    ExcludeRules = $SettingsFromFile.ExcludeRules
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

Write-Host ('[status]Running PSScriptAnalyzer on: ' + $FolderPath_Module)
Write-Host ('[status]PSScriptAnalyzer Settings File: ' + $SettingsFile)

$ScriptAnalyzerResults = Invoke-ScriptAnalyzer -Path:($FolderPath_Module) -Recurse -Settings $settingsObject # -ExcludeRule PSAvoidUsingPlainTextForPassword, PSAvoidOverwritingBuiltInCmdlets, PSAvoidUsingConvertToSecureStringWithPlainText
If (-not [System.String]::IsNullOrEmpty($ScriptAnalyzerResults))
{
    $ScriptAnalyzerResults | ForEach-Object {
        Write-Error ('[PSScriptAnalyzer][' + $_.Severity + '][' + $_.RuleName + '] ' + $_.Message + ' found in "' + $_.ScriptPath + '" at line ' + $_.Line + ':' + $_.Column)
    }
}
Else
{
    Write-Host ('[success]ScriptAnalyzer returned no results')
}