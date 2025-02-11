# This file should build the env needed to test on a windows agent.

# Dot-source the variables for setupAgent/ migration tests:
. $PSScriptRoot\BuildVariables.ps1
# Dot-source private functions
$Private = @( Get-ChildItem -Path "$PSScriptRoot/../Private/*.ps1" -Recurse)
Foreach ($Import in $Private) {
    Try {
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}


