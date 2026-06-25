function Invoke-WithProgressHeartbeat {
    <#
    .SYNOPSIS
    Runs a blocking scriptblock in a background runspace while invoking a heartbeat on the caller's thread.

    .DESCRIPTION
    Used when native commands (e.g. icacls) block a runspace and prevent timer-based progress updates.
    The scriptblock runs asynchronously; the caller polls and invokes -OnHeartbeat on the main thread.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnHeartbeat,

        [Parameter(Mandatory = $false)]
        [int]$HeartbeatIntervalSeconds = 120,

        [Parameter(Mandatory = $false)]
        [switch]$PrepareNtfsRunspace
    )

    $runspace = $null
    $powershell = $null

    try {
        $initialSession = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $runspace = [runspacefactory]::CreateRunspace($initialSession)
        $runspace.Open()

        if ($PrepareNtfsRunspace) {
            $privateRoot = Split-Path $PSScriptRoot -Parent
            $functionPaths = @(
                (Join-Path $privateRoot 'SystemInfo\Get-WindowsDrive.ps1')
                (Join-Path $privateRoot 'Logging\Write-ToLog.ps1')
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

        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        $null = $powershell.AddScript($ScriptBlock)
        if ($ArgumentList) {
            foreach ($arg in $ArgumentList) {
                $null = $powershell.AddArgument($arg)
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
