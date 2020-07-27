# Load all functions from public and private folders
#$Public = @( Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -Recurse )
#$Private = @( Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -Recurse)
$Public = @(Get-ChildItem -Path "$PSScriptRoot/Powershell/*.ps1" -Recurse)
Foreach ($Import in @($Public + $Private)) {
    Try {
        . $Import.FullName
    }
    Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}
