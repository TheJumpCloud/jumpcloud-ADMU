function Invoke-WithProgressHeartbeat {
    <#
    .SYNOPSIS
    Runs a blocking scriptblock in a background runspace while invoking a heartbeat on the caller's thread.

    .DESCRIPTION
    Used when native commands (e.g. icacls) block a runspace and prevent timer-based progress updates.
    The scriptblock runs asynchronously; the caller polls and invokes -OnHeartbeat on the main thread.

    When -PrepareNtfsRunspace is used with PermissionSourceSID, PermissionTargetSID, and
    PermissionProfilePath in -RunspaceVariables, Set-RegPermission is invoked via script text
    parsed in the child runspace so variables resolve correctly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [hashtable]$RunspaceVariables,

        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnHeartbeat,

        [Parameter(Mandatory = $false)]
        [int]$HeartbeatIntervalSeconds = 120,

        [Parameter(Mandatory = $false)]
        [switch]$PrepareNtfsRunspace
    )

    $useNtfsPermissionScript = $false
    if ($PrepareNtfsRunspace) {
        if (-not $RunspaceVariables) {
            throw 'RunspaceVariables is required when PrepareNtfsRunspace is specified.'
        }
        foreach ($requiredKey in @('PermissionSourceSID', 'PermissionTargetSID', 'PermissionProfilePath')) {
            if (-not $RunspaceVariables.ContainsKey($requiredKey) -or [string]::IsNullOrWhiteSpace([string]$RunspaceVariables[$requiredKey])) {
                throw "RunspaceVariables must include a non-empty value for $requiredKey when PrepareNtfsRunspace is specified."
            }
        }
        $useNtfsPermissionScript = $true
    } elseif (-not $ScriptBlock) {
        throw 'ScriptBlock is required when PrepareNtfsRunspace is not specified.'
    }

    $runspace = $null
    $powershell = $null

    try {
        $initialSession = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $runspace = [runspacefactory]::CreateRunspace($initialSession)
        $runspace.Open()

        if ($PrepareNtfsRunspace) {
            $privateRoot = Split-Path $PSScriptRoot -Parent
            $functionPaths = @(
                (Join-Path (Join-Path $privateRoot 'SystemInfo') 'Get-WindowsDrive.ps1')
                (Join-Path (Join-Path $privateRoot 'Logging') 'Write-ToLog.ps1')
                (Join-Path $PSScriptRoot 'Set-RegPermission.ps1')
            )
            $loadPs = [powershell]::Create()
            $loadPs.Runspace = $runspace
            foreach ($functionPath in $functionPaths) {
                if (-not (Test-Path $functionPath)) {
                    throw "Required function file not found for NTFS runspace: $functionPath"
                }
                $null = $loadPs.AddScript(". '$($functionPath.Replace("'", "''"))'")
            }
            $loadPs.Invoke() | Out-Null
            if ($loadPs.HadErrors) {
                throw ($loadPs.Streams.Error | ForEach-Object { $_.Exception.Message }) -join '; '
            }
            $loadPs.Dispose()
        }

        if ($RunspaceVariables) {
            foreach ($key in $RunspaceVariables.Keys) {
                $null = $runspace.SessionStateProxy.SetVariable($key, $RunspaceVariables[$key])
            }
        }

        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace

        if ($useNtfsPermissionScript) {
            # Script text is parsed in the child runspace so SessionStateProxy variables bind correctly.
            $null = $powershell.AddScript(@'
Set-RegPermission -SourceSID $PermissionSourceSID -TargetSID $PermissionTargetSID -FilePath $PermissionProfilePath -Recursive -ErrorAction Stop
'@)
        } else {
            $null = $powershell.AddScript($ScriptBlock)
            if ($ArgumentList) {
                foreach ($arg in $ArgumentList) {
                    $null = $powershell.AddArgument($arg)
                }
            }
        }

        $async = $powershell.BeginInvoke()
        $intervalMs = [math]::Max(1, $HeartbeatIntervalSeconds) * 1000

        while (-not $async.IsCompleted) {
            if ($async.AsyncWaitHandle.WaitOne($intervalMs)) {
                break
            }
            if ($OnHeartbeat) {
                & $OnHeartbeat
            }
        }

        $result = $powershell.EndInvoke($async)
        if ($powershell.HadErrors) {
            throw ($powershell.Streams.Error | ForEach-Object { $_.Exception.Message }) -join '; '
        }

        return $result
    } finally {
        if ($powershell) {
            $powershell.Dispose()
        }
        if ($runspace) {
            $runspace.Close()
            $runspace.Dispose()
        }
    }
}
