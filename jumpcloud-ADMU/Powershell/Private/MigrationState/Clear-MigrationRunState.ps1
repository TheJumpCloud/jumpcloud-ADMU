<#
.SYNOPSIS
    Removes the run-state marker that Start-Migration keeps while a migration is in progress.

.DESCRIPTION
    A failure to remove the marker is logged and not thrown.
#>
function Clear-MigrationRunState {
    [CmdletBinding()]
    param ()

    $keyPath = 'HKLM:\SOFTWARE\JCADMU\RunState'
    try {
        if (Test-Path -LiteralPath $keyPath) {
            Remove-Item -LiteralPath $keyPath -Recurse -Force -ErrorAction Stop
            Write-ToLog -Message "Run state marker cleared" -Level Verbose -Step "Clear-MigrationRunState"
        }
    } catch {
        Write-ToLog -Message "Could not clear the run state marker: $($_.Exception.Message)" -Level Verbose -Step "Clear-MigrationRunState"
    }
}
