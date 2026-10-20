<#
.SYNOPSIS
    Decides whether a PreviousSID value found in a user's registry hive was left behind by an interrupted migration.

.DESCRIPTION
    A completed migration writes the source user's SID into the hive of the new local user. The value
    therefore never equals the SID of the account that owns the hive. A value that equals the owner's own SID
    was written into the source user's hive by an earlier migration that stopped after the hive files were
    swapped (Start-Migration renames the merged NTUSER.DAT.BAK over NTUSER.DAT before it updates ProfileList).

    The value is also treated as stale only while ProfileList still maps the SID to its original folder. After a
    completed swap, the source SID maps to a folder with the .ADMU suffix.

.PARAMETER PreviousSid
    The data of the PreviousSID registry value.

.PARAMETER UserSid
    The SID of the account that owns the hive being checked.

.PARAMETER ProfileImagePath
    The ProfileImagePath that ProfileList currently holds for UserSid.

.OUTPUTS
    [boolean] - Returns $true when the value is a stale leftover, $false otherwise.
#>
function Test-StalePreviousSID {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PreviousSid,
        [Parameter(Mandatory = $true)]
        [string]$UserSid,
        [Parameter(Mandatory = $false)]
        [string]$ProfileImagePath
    )

    if ($PreviousSid -ne $UserSid) {
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($ProfileImagePath)) {
        return $false
    }
    if ($ProfileImagePath -match '\.ADMU$') {
        return $false
    }
    return $true
}
