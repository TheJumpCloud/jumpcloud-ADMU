<#
.SYNOPSIS
    Writes the run-state marker that Start-Migration keeps while a migration is in progress.

.DESCRIPTION
    Start-Migration writes the marker after validation and clears it when the run ends. A run that is killed or
    that stops without reaching its end{} block leaves the marker behind. The next run reads it with
    Get-MigrationRunState and logs the recovery that fits the phase.

    Phases:
    - started: the run began. The profile swap has not happened.
    - swapped: ProfileList maps the source SID to the .ADMU folder and the target SID to the original folder.

    The marker lives in HKLM:\SOFTWARE\JCADMU\RunState. A failure to write it is logged and never stops the migration.

.PARAMETER Phase
    The phase the run has reached.

.PARAMETER SourceSID
    The SID of the user being migrated.

.PARAMETER SourceProfilePath
    The ProfileImagePath of the source user when the run started.

.PARAMETER TargetUserName
    The username of the local account the run creates.

.PARAMETER TargetSID
    The SID of the local account. Known once the account exists.

.OUTPUTS
    [boolean] - $true when the marker was written, $false otherwise.
#>
function Set-MigrationRunState {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('started', 'swapped')]
        [string]$Phase,
        [Parameter(Mandatory = $true)]
        [string]$SourceSID,
        [Parameter(Mandatory = $true)]
        [string]$SourceProfilePath,
        [Parameter(Mandatory = $true)]
        [string]$TargetUserName,
        [Parameter(Mandatory = $false)]
        [string]$TargetSID = ''
    )

    $keyPath = 'HKLM:\SOFTWARE\JCADMU\RunState'
    try {
        if (-not (Test-Path -LiteralPath $keyPath)) {
            New-Item -Path $keyPath -Force -ErrorAction Stop | Out-Null
        }
        $values = [Ordered]@{
            Phase             = $Phase
            ProcessId         = "$PID"
            SourceSID         = $SourceSID
            SourceProfilePath = $SourceProfilePath
            TargetUserName    = $TargetUserName
            TargetSID         = $TargetSID
        }
        # StartTime belongs to the run, so only the first phase sets it
        if ($Phase -eq 'started') {
            $values['StartTime'] = (Get-Date).ToString('o')
        }
        foreach ($name in $values.Keys) {
            Set-ItemProperty -LiteralPath $keyPath -Name $name -Value ([string]$values[$name]) -Force -ErrorAction Stop
        }
        Write-ToLog -Message "Run state set to '$Phase'" -Level Verbose -Step "Set-MigrationRunState"
        return $true
    } catch {
        Write-ToLog -Message "Could not write the run state marker: $($_.Exception.Message)" -Level Verbose -Step "Set-MigrationRunState"
        return $false
    }
}
