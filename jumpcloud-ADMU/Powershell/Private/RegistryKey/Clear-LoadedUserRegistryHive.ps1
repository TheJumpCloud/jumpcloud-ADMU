<#
.SYNOPSIS
    Unloads the ADMU registry hives of a user when they are still loaded under HKEY_USERS.

.DESCRIPTION
    Start-Migration loads a user's NTUSER.DAT.BAK as HKU\<SID>_admu and UsrClass.dat.bak as
    HKU\<SID>_Classes_admu. A failure or a throw between the load and the unload leaves them loaded, and a loaded hive
    blocks the file restore and the profile removal that a rollback needs.

    The function is best effort. It logs each unload and each failure, and it never throws, so a rollback or the
    original error is not replaced by an unload error.

.PARAMETER UserSid
    The SID whose hives should be unloaded.

.PARAMETER ProfilePath
    The profile folder the hives were loaded from.
#>
function Clear-LoadedUserRegistryHive {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$UserSid,
        [Parameter(Mandatory = $true)]
        [System.String]$ProfilePath
    )

    try {
        $loadedHives = REG QUERY HKU *>&1
        $hivesToUnload = @(
            @{ Name = "$($UserSid)_admu"; Hive = "root" },
            @{ Name = "$($UserSid)_Classes_admu"; Hive = "classes" }
        )
        foreach ($hiveToUnload in $hivesToUnload) {
            if ($loadedHives -match "\\$([regex]::Escape($hiveToUnload.Name))\s*$") {
                Write-ToLog "Unloading HKU\$($hiveToUnload.Name)" -Level Verbose -Step "Clear-LoadedUserRegistryHive"
                Set-UserRegistryLoadState -op "Unload" -ProfilePath $ProfilePath -UserSid $UserSid -hive $hiveToUnload.Hive
            }
        }
    } catch {
        Write-ToLog "Could not unload HKU\$($UserSid) hives: $($_.Exception.Message)" -Level Warning -Step "Clear-LoadedUserRegistryHive"
    }
}
