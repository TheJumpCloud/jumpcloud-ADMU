# Load all functions from private folders
$Private = @( Get-ChildItem -Path "$PSScriptRoot/Powershell/Private/*.ps1" -Recurse)
Foreach ($Import in $Private) {
    Try {
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

# Load all public functions:
$Public = @( Get-ChildItem -Path "$PSScriptRoot/Powershell/Public/*.ps1" -Recurse)
Foreach ($Import in $Public) {
    Try {
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

# . "$PSScriptRoot\Powershell\Start-Migration.ps1"

Export-ModuleMember -Function $Public.BaseName
