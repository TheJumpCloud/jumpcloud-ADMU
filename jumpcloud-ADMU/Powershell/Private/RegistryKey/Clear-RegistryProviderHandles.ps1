function Clear-RegistryProviderHandles {
    <#
    .SYNOPSIS
        Releases PowerShell registry provider handles that can block REG UNLOAD.

    .DESCRIPTION
        The HKEY_USERS PSDrive and cached RegistryKey objects from the PowerShell
        provider commonly prevent REG UNLOAD of manually loaded profile hives.
        This removes the drive (if present) and forces a full GC finalizer pass
        so handles held by the ADMU process are released before unload retries.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]
        $Remount
    )

    if ("HKEY_USERS" -in @(Get-PSDrive | Select-Object -ExpandProperty Name)) {
        try {
            Remove-PSDrive -Name "HKEY_USERS" -Force -ErrorAction Stop
            Write-ToLog -Message "Removed HKEY_USERS PSDrive to release registry provider handles" -Level Verbose -Step "Clear-RegistryProviderHandles"
        } catch {
            Write-ToLog -Message "Could not remove HKEY_USERS PSDrive: $($_.Exception.Message)" -Level Verbose -Step "Clear-RegistryProviderHandles"
        }
    }

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()

    if ($Remount) {
        Set-HKEYUserMount
    }
}
