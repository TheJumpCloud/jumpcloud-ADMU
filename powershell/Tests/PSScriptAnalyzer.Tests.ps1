$FolderPath_Module = 'C:\agent\_work\2\s\powershell\'

Write-Host ('[status]Running PSScriptAnalyzer on: ' + $FolderPath_Module)
$ScriptAnalyzerResults = Invoke-ScriptAnalyzer -Path:($FolderPath_Module) -Recurse -ExcludeRule PSAvoidUsingWMICmdlet,PSAvoidUsingPlainTextForPassword,PSAvoidUsingUsernameAndPasswordParams,PSAvoidUsingInvokeExpression,PSUseDeclaredVarsMoreThanAssignments,PSUseSingularNouns,PSAvoidGlobalVars,PSUseShouldProcessForStateChangingFunctions,PSAvoidUsingWriteHost


If ($ScriptAnalyzerResults)
{
    $ScriptAnalyzerResults
    Write-Error ('Go fix the ScriptAnalyzer results!')
}
Else
{
    Write-Host ('[success]ScriptAnalyzer returned no results')
}
