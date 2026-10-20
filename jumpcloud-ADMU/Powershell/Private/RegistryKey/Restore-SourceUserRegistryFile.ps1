<#
.SYNOPSIS
    Puts a source user's original NTUSER.DAT and UsrClass.dat back after a migration that failed before the profile swap.

.DESCRIPTION
    Start-Migration renames the source user's NTUSER.DAT and UsrClass.dat to NTUSER_original_<timestamp>.DAT and
    UsrClass_original_<timestamp>.dat, then renames the merged hive backups into their place. A failure after that
    leaves the user signed in with the merged hive, and its Software\JCADMU key makes the first-login UWP app run.

    For each hive, when the original file exists, the function moves the current file to a _migrated name, as
    Start-Reversion does, and moves the original back. Each hive is handled on its own, so a run that renamed only
    NTUSER.DAT is restored too. The hives must be unloaded first.

.PARAMETER ProfilePath
    The source user's profile folder.

.PARAMETER Timestamp
    The timestamp Start-Migration used in the _original_ file names, in the format yyyy-MM-dd-HHmmss.

.OUTPUTS
    [string[]] - The names of the hive files that were restored.
#>
function Restore-SourceUserRegistryFile {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ProfilePath,
        [Parameter(Mandatory = $true)]
        [System.String]$Timestamp
    )

    $usrClassFolder = Join-Path $ProfilePath "AppData\Local\Microsoft\Windows"
    $hiveFiles = @(
        @{
            Name     = "NTUSER.DAT"
            Current  = Join-Path $ProfilePath "NTUSER.DAT"
            Original = Join-Path $ProfilePath "NTUSER_original_$Timestamp.DAT"
            Migrated = Join-Path $ProfilePath "NTUSER_migrated.DAT"
        },
        @{
            Name     = "UsrClass.dat"
            Current  = Join-Path $usrClassFolder "UsrClass.dat"
            Original = Join-Path $usrClassFolder "UsrClass_original_$Timestamp.dat"
            Migrated = Join-Path $usrClassFolder "UsrClass_migrated.dat"
        }
    )

    $restored = @()
    foreach ($hiveFile in $hiveFiles) {
        if (-not (Test-Path -LiteralPath $hiveFile.Original)) {
            continue
        }
        try {
            if (Test-Path -LiteralPath $hiveFile.Current) {
                Move-Item -LiteralPath $hiveFile.Current -Destination $hiveFile.Migrated -Force -ErrorAction Stop
            }
            Move-Item -LiteralPath $hiveFile.Original -Destination $hiveFile.Current -Force -ErrorAction Stop
            Write-ToLog "Restored $($hiveFile.Name) from $($hiveFile.Original)" -Level Info -Step "Restore-SourceUserRegistryFile"
            $restored += $hiveFile.Name
        } catch {
            Write-ToLog "Could not restore $($hiveFile.Name) from '$($hiveFile.Original)' to '$($hiveFile.Current)': $($_.Exception.Message). Restore it manually or run Start-Reversion." -Level Warning -Step "Restore-SourceUserRegistryFile"
        }
    }
    return $restored
}
