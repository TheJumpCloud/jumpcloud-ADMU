<#
.SYNOPSIS
    Reads the run-state marker left by Start-Migration.

.OUTPUTS
    [PSCustomObject] with Phase, StartTime, ProcessId, SourceSID, SourceProfilePath, TargetUserName and TargetSID,
    or $null when no marker exists.
#>
function Get-MigrationRunState {
    [CmdletBinding()]
    param ()

    $keyPath = 'HKLM:\SOFTWARE\JCADMU\RunState'
    if (-not (Test-Path -LiteralPath $keyPath)) {
        return $null
    }
    try {
        $properties = Get-ItemProperty -LiteralPath $keyPath -ErrorAction Stop
    } catch {
        Write-ToLog -Message "Could not read the run state marker: $($_.Exception.Message)" -Level Verbose -Step "Get-MigrationRunState"
        return $null
    }
    if ([string]::IsNullOrEmpty($properties.Phase)) {
        return $null
    }
    $processId = 0
    [void][int]::TryParse([string]$properties.ProcessId, [ref]$processId)
    return [PSCustomObject]@{
        Phase             = [string]$properties.Phase
        StartTime         = [string]$properties.StartTime
        ProcessId         = $processId
        SourceSID         = [string]$properties.SourceSID
        SourceProfilePath = [string]$properties.SourceProfilePath
        TargetUserName    = [string]$properties.TargetUserName
        TargetSID         = [string]$properties.TargetSID
    }
}
