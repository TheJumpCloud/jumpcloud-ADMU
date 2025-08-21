# Set-SystemAttribute.ps1
function Set-SystemAttribute {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$MigrationStatus,

        [Parameter(Mandatory = $true)]
        [string]$MigrationPercentage,

        [Parameter(Mandatory = $true)]
        [string]$UserSID,

        [Parameter(Mandatory = $true)]
        [string]$MigrationUsername,

        [Parameter(Mandatory = $true)]
        [string]$UserID,

        [Parameter(Mandatory = $true)]
        [string]$DeviceID
    )

    $description = [PSCustomObject]@{
        MigrationStatus     = $MigrationStatus
        MigrationPercentage = $MigrationPercentage
        UserSID             = $UserSID
        MigrationUsername   = $MigrationUsername
        UserID              = $UserID
        DeviceID            = $DeviceID
    }
    Invoke-SystemContextAPI -Method PUT -Endpoint 'Systems' -Body @{'description' = ($description | ConvertTo-Json -Compress) }
}
