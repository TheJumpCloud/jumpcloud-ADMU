function Test-WindowsARSO {
    <#
    .SYNOPSIS
    Tests whether a user is enabled for Automatic Restart Sign-On (ARSO).

    .DESCRIPTION
    Checks the global policy and per-user registry keys to determine if ARSO
    is enabled for a specific user SID. Returns $true if enabled, $false if disabled.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserSID
    )

    # 1. Check if ARSO is globally disabled via policy
    $globalPolicyPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
    $globalPolicy = Get-ItemProperty -Path $globalPolicyPath -Name 'DisableAutomaticRestartSignOn' -ErrorAction SilentlyContinue

    if ($null -ne $globalPolicy -and $globalPolicy.DisableAutomaticRestartSignOn -eq 1) {
        return $false
    }

    # 2. Check per-user ARSO registry key
    $userARSOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$UserSID"

    if (Test-Path -Path $userARSOPath) {
        $optOutValue = Get-ItemPropertyValue -Path $userARSOPath -Name 'OptOut' -ErrorAction SilentlyContinue

        # If OptOut is 1, ARSO is explicitly disabled for the user. If 0, it is enabled.
        if ($optOutValue -eq 1) {
            return $false
        } else {
            return $true
        }
    }

    # If the user ARSO key doesn't exist, it defaults to false (not explicitly configured)
    return $false
}
