$FolderPath_Module = (Get-Item -Path($PSScriptRoot)).Parent.FullName

Write-Host ('[status]Running PSScriptAnalyzer on: ' + $FolderPath_Module)
$ScriptAnalyzerResults = Invoke-ScriptAnalyzer -Path:($FolderPath_Module) -Recurse -ExcludeRule PSAvoidUsingWMICmdlet, PSAvoidUsingPlainTextForPassword, PSAvoidUsingUsernameAndPasswordParams, PSAvoidUsingInvokeExpression, PSUseDeclaredVarsMoreThanAssignments, PSUseSingularNouns, PSAvoidGlobalVars, PSUseShouldProcessForStateChangingFunctions, PSAvoidUsingWriteHost, PSAvoidUsingPositionalParameters, PSUseApprovedVerbs, PSUseToExportFieldsInManifest, PSUseOutputTypeCorrectly
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