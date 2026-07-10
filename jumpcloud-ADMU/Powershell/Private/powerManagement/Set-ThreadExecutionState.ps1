function Set-ThreadExecutionState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'Enable or disable Windows sleep prevention for this session. Default is $true.')]
        [bool]$enable = $true
    )
    begin {
        if (-not ('PowerManagement' -as [type])) {
            Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class PowerManagement {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern uint SetThreadExecutionState(uint esFlags);

    public const uint ES_CONTINUOUS = 0x80000000;
    public const uint ES_SYSTEM_REQUIRED = 0x00000001;
    public const uint ES_DISPLAY_REQUIRED = 0x00000002;
}
'@
        }
    }
    process {
        $resultState = 'DISABLED'
        switch ($enable) {
            $true {
                $flags = [PowerManagement]::ES_CONTINUOUS -bor `
                    [PowerManagement]::ES_SYSTEM_REQUIRED -bor `
                    [PowerManagement]::ES_DISPLAY_REQUIRED
                $apiResult = [PowerManagement]::SetThreadExecutionState($flags)
                if ($apiResult -eq 0) {
                    $resultState = 'FAILED'
                } else {
                    Write-Host 'Enabled Windows sleep prevention for this session.'
                    $resultState = 'ENABLED'
                }
            }
            $false {
                $null = [PowerManagement]::SetThreadExecutionState([PowerManagement]::ES_CONTINUOUS)
                Write-Host 'Disabled Windows sleep prevention for this session.'
                $resultState = 'DISABLED'
            }
        }
    }
    end {
        return $resultState
    }
}
