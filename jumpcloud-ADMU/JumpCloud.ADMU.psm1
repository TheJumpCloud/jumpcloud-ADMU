# Load all functions from public and private folders
#$Public = @( Get-ChildItem -Path "$PSScriptRoot/Public/*.ps1" -Recurse )
#$Private = @( Get-ChildItem -Path "$PSScriptRoot/Private/*.ps1" -Recurse)
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Powershell\Functions.ps1")

Write-Host $PSScriptRoot
. "$PSScriptRoot\Powershell\Functions.ps1"

# Foreach ($Import in @($Public + $Private)) {
#     Try {
#         Write-Host $Import.FullName
#         . $Import.FullName
#     }
#     Catch {
#         Write-Error -Message "Failed to import function $($Import.FullName): $_"
#     }
# }
