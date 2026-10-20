<#
.SYNOPSIS
    Builds the validation message for a local account that an earlier ADMU run created and left behind.

.DESCRIPTION
    Start-Migration stops when a local account with the target username already exists. When that account has the
    description "Created By JumpCloud ADMU", an earlier run created it. The message names the account and its profile
    path, and says which recovery applies:

    - Pre-swap: ProfileList still maps the source SID to its original folder. The account owns an empty profile that
      ADMU created, and the account and that profile can be removed.
    - Post-swap: ProfileList maps the source SID to a folder with the .ADMU suffix. The account owns the user's
      original folder, so it must not be removed. Start-Reversion restores the original profile.

.PARAMETER JumpCloudUserName
    The username of the leftover local account.

.PARAMETER SourceSID
    The SID of the user being migrated.

.PARAMETER SourceProfileImagePath
    The ProfileImagePath that ProfileList holds for SourceSID.

.PARAMETER JumpCloudManaged
    Set when the device is also associated to a JumpCloud user with the same username.

.OUTPUTS
    [string]
#>
function Get-LeftoverAdmuUserMessage {
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$JumpCloudUserName,
        [Parameter(Mandatory = $true)]
        [string]$SourceSID,
        [Parameter(Mandatory = $true)]
        [string]$SourceProfileImagePath,
        [Parameter(Mandatory = $false)]
        [bool]$JumpCloudManaged = $false
    )

    $leftoverProfilePath = $null
    try {
        $leftoverSid = (Get-LocalUser -Name $JumpCloudUserName -ErrorAction Stop).SID.Value
        $leftoverProfilePath = Get-ProfileImagePath -UserSid $leftoverSid
    } catch {
        Write-ToLog -Message "Could not read the profile path of local user '$JumpCloudUserName': $($_.Exception.Message)" -Level Verbose -Step "Get-LeftoverAdmuUserMessage"
    }

    $msg = "The local account '$JumpCloudUserName' already exists on this device with the description 'Created By JumpCloud ADMU'. An earlier ADMU run created it and did not finish."
    if ([string]::IsNullOrWhiteSpace($leftoverProfilePath)) {
        $msg += " The account has no profile yet. To resolve the issue, remove the local account '$JumpCloudUserName' before attempting migration again."
    } elseif ($SourceProfileImagePath -match '\.ADMU$') {
        $msg += " The account's profile path is '$leftoverProfilePath', and the source user's profile path is '$SourceProfileImagePath', so the run got past the profile swap. Do not remove the account or the folder. To resolve the issue, run Start-Reversion -UserSID $SourceSID before attempting migration again."
    } elseif ($leftoverProfilePath -eq $SourceProfileImagePath) {
        $msg += " The account's profile path is '$leftoverProfilePath', which is also the source user's profile path. Do not remove that folder. To resolve the issue, review the ProfileList entries for the account and for SID $SourceSID before attempting migration again."
    } else {
        $msg += " The account's profile path is '$leftoverProfilePath', and the source user's profile still maps to '$SourceProfileImagePath', so the run stopped before the profile swap. To resolve the issue, remove the local account '$JumpCloudUserName' and its profile folder '$leftoverProfilePath' before attempting migration again."
    }
    if ($JumpCloudManaged) {
        $msg += " The device is also associated to a JumpCloud user with the same username. Unbind that association first."
    }
    return $msg
}
