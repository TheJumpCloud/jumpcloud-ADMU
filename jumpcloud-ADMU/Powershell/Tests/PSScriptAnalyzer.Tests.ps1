$FolderPath_Module = (Get-Item -Path($PSScriptRoot)).Parent.FullName

################################################################################
# Rules Skipped:
# PSAvoidUsingWMICmdlet:
# PSAvoidUsingPlainTextForPassword:
# PSAvoidUsingUsernameAndPasswordParams
# PSAvoidUsingInvokeExpression
# PSUseDeclaredVarsMoreThanAssignments
# PSUseSingularNouns
# PSAvoidGlobalVars
# PSUseShouldProcessForStateChangingFunctions
# PSAvoidUsingWriteHost
# PSAvoidUsingPositionalParameters
# PSUseApprovedVerbs
# PSUseToExportFieldsInManifest
# PSUseOutputTypeCorrectly
# PSAvoidOverwritingBuiltInCmdlets
# PSAvoidUsingConvertToSecureStringWithPlainText
################################################################################

Write-Host ('[status]Running PSScriptAnalyzer on: ' + $FolderPath_Module)
$ScriptAnalyzerResults = Invoke-ScriptAnalyzer -Path:($FolderPath_Module) -Recurse -Settings $PSScriptRoot\PSScriptAnalyzerSettings.psd1 # -ExcludeRule PSAvoidUsingPlainTextForPassword, PSAvoidOverwritingBuiltInCmdlets, PSAvoidUsingConvertToSecureStringWithPlainText
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