<#
.SYNOPSIS
    Removes a stale PreviousSID marker from a loaded user registry hive.

.DESCRIPTION
    Deletes the previousSid and previousProfilePath values from HKEY_USERS\<UserSid>_admu\Software\JCADMU.
    The JCADMU key is deleted too when nothing else remains in it. Start-Migration writes a new marker into the
    target hive only when the key does not exist after the registry copy, so an empty key left here would
    suppress the marker for the migration that is about to run.

    The hive that ADMU loads under HKEY_USERS\<UserSid>_admu is NTUSER.DAT.BAK, the copy that Backup-RegistryHive
    made for this run. The live NTUSER.DAT is not modified.

.PARAMETER UserSid
    The SID of the account whose loaded hive holds the stale marker.
#>
function Remove-StalePreviousSID {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$UserSid
    )

    $softwarePath = "$($UserSid)_admu\Software"
    $jcadmuKey = $null
    $softwareKey = $null
    try {
        $jcadmuKey = [Microsoft.Win32.Registry]::Users.OpenSubKey("$softwarePath\JCADMU", $true)
        if ($null -eq $jcadmuKey) {
            return
        }
        foreach ($valueName in @('previousSid', 'previousProfilePath')) {
            $jcadmuKey.DeleteValue($valueName, $false)
        }
        $isEmpty = ($jcadmuKey.ValueCount -eq 0) -and ($jcadmuKey.SubKeyCount -eq 0)
        $jcadmuKey.Close()
        $jcadmuKey.Dispose()
        $jcadmuKey = $null
        if ($isEmpty) {
            $softwareKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($softwarePath, $true)
            $softwareKey.DeleteSubKey('JCADMU', $false)
        }
    } finally {
        if ($null -ne $jcadmuKey) {
            $jcadmuKey.Close()
            $jcadmuKey.Dispose()
        }
        if ($null -ne $softwareKey) {
            $softwareKey.Close()
            $softwareKey.Dispose()
        }
    }
    Write-ToLog "Removed the stale PreviousSID marker from the loaded registry hive for $UserSid" -Level Verbose -Step "Remove-StalePreviousSID"
}
