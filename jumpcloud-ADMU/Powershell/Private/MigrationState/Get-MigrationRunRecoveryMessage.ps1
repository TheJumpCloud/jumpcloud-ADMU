<#
.SYNOPSIS
    Builds the message that tells an operator how to recover from an interrupted ADMU run.

.PARAMETER RunState
    The marker returned by Get-MigrationRunState.

.PARAMETER ProcessRunning
    Set when the process that wrote the marker is still running.

.OUTPUTS
    [string]
#>
function Get-MigrationRunRecoveryMessage {
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RunState,
        [Parameter(Mandatory = $false)]
        [bool]$ProcessRunning = $false
    )

    if ($ProcessRunning) {
        return "A run that started at $($RunState.StartTime) is recorded for process $($RunState.ProcessId), and that process is still running. Another ADMU run may be active on this device."
    }

    $msg = "A previous ADMU run did not finish. It started at $($RunState.StartTime) for SID $($RunState.SourceSID), and process $($RunState.ProcessId) is no longer running. The last step in the log before this run shows where it stopped."
    switch ($RunState.Phase) {
        'swapped' {
            $msg += " The run stopped after the profile swap, so ProfileList maps SID $($RunState.SourceSID) to a folder with the .ADMU suffix and the local account '$($RunState.TargetUserName)' owns '$($RunState.SourceProfilePath)'. Run Start-Reversion -UserSID $($RunState.SourceSID) to restore the original profile before migrating again."
        }
        default {
            $msg += " The run stopped before the profile swap. Confirm that ProfileList still maps SID $($RunState.SourceSID) to '$($RunState.SourceProfilePath)'. If the local account '$($RunState.TargetUserName)' exists with the description 'Created By JumpCloud ADMU', remove the account and its profile folder (usually '$($RunState.SourceProfilePath).000') before migrating again."
        }
    }
    return $msg
}
