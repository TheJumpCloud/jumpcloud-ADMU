function Set-WindowsARSO {
    <#
    .SYNOPSIS
    Enables or disables Automatic Restart Sign-On (ARSO) for a specific user.

    .DESCRIPTION
    Modifies the OptOut DWORD in the user's ARSO registry path to toggle the feature.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserSID,

        [Parameter(Mandatory = $true)]
        [bool]$Enable
    )

    $userARSOPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserARSO\$UserSID"

    # Create the registry path if it does not exist
    if (-not (Test-Path -Path $userARSOPath)) {
        New-Item -Path $userARSOPath -Force | Out-Null
    }

    # OptOut: 1 = Disabled, 0 = Enabled
    $optOutValue = if ($Enable) { 0 } else { 1 }

    Set-ItemProperty -Path $userARSOPath -Name 'OptOut' -Value $optOutValue -Type DWord -Force
}