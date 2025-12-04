function New-RegPermissionTask {
    <#
    .SYNOPSIS
    Creates a scheduled task to set recursive NTFS permissions on user profile at first login.

    .DESCRIPTION
    This function creates and registers a scheduled task that runs uwp_jcadmu.exe with the -SetPermissions
    flag to apply recursive NTFS permissions to a user profile. The task runs as SYSTEM at user logon,
    with high priority, retry logic, and automatic self-deletion upon success.

    .PARAMETER ProfilePath
    The full path to the user profile directory where permissions will be set.

    .PARAMETER TargetSID
    The SID of the target user (new JumpCloud user).

    .PARAMETER SourceSID
    The SID of the source user (original domain user).

    .PARAMETER TaskUser
    The username of the JumpCloud user for whom the task will trigger on logon.

    .EXAMPLE
    New-RegPermissionTask -ProfilePath "C:\Users\jdoe" -TargetSID "S-1-5-21-..." -SourceSID "S-1-5-21-..." -TaskUser "jdoe"

    .OUTPUTS
    Returns $true if the task was created successfully, $false otherwise.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfilePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetSID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceSID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskUser
    )

    begin {
        Write-ToLog -Message "New-RegPermissionTask: Creating scheduled task for deferred permissions"
    }

    process {
        try {
            # Determine Windows drive (usually C:)
            $windowsDrive = $env:SystemDrive
            if ([string]::IsNullOrEmpty($windowsDrive)) {
                $windowsDrive = "C:"
            }

            # Build argument string with parameters (no quotes needed - they cause issues with SID parsing)
            $taskArguments = "-SetPermissions 1 -SourceSID $SourceSID -TargetSID $TargetSID -ProfilePath `"$ProfilePath`""

            $taskAction = New-ScheduledTaskAction -Execute "$windowsDrive\Windows\uwp_jcadmu.exe" -Argument $taskArguments
            $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $TaskUser
            $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
            $taskSettings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -RestartInterval (New-TimeSpan -Minutes 1) `
                -RestartCount 3 `
                -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
                -Priority 4

            $taskName = "ADMU-SetPermissions-$TargetSID"
            Register-ScheduledTask -TaskName $taskName `
                -Action $taskAction `
                -Trigger $taskTrigger `
                -Principal $taskPrincipal `
                -Settings $taskSettings `
                -Description "JumpCloud ADMU: Set recursive NTFS permissions on user profile (runs once on first login)" `
                -Force | Out-Null

            Write-ToLog -Message "Created scheduled task '$taskName' with parameters for deferred permissions"
            Write-ToLog -Message "Task arguments: $taskArguments"

            return $true
        } catch {
            Write-ToLog -Message "Warning: Failed to create scheduled task for deferred permissions: $_" -Level Warning
            return $false
        }
    }
}
