$Public = @(Get-ChildItem -Path "$PSScriptRoot\Powershell\Start-Migration.ps1")

. "$PSScriptRoot\Powershell\Start-Migration.ps1"

Export-ModuleMember -Function $Public.BaseName
