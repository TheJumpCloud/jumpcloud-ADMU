function Test-LocalUsernameExist {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $JumpCloudUserName
    )

    # Default flags
    $exists = $false
    $jumpCloudCreated = $false
    $jumpCloudManaged = $false
    $admuCreated = $false

    # Check local user existence & description
    try {
        $localUser = Get-LocalUser -Name $JumpCloudUserName -ErrorAction SilentlyContinue
    } catch {
        $localUser = $null
    }

    if ($null -ne $localUser) {
        $exists = $true

        $description = [string]$localUser.Description

        if (-not [string]::IsNullOrWhiteSpace($description)) {
            # Created by JumpCloud
            if ($description -eq 'Created by Jumpcloud') {
                $jumpCloudCreated = $true
            }

            # Created by JumpCloud ADMU
            if ($description -eq 'Created By JumpCloud ADMU') {
                $admuCreated = $true
            }
        }
    }

    # managedUsers.json (JC association)
    $managedUsersPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\managedUsers.json'

    if (Test-Path -LiteralPath $managedUsersPath) {
        try {
            $rawJson = Get-Content -LiteralPath $managedUsersPath -Raw -ErrorAction Stop

            if (-not [string]::IsNullOrWhiteSpace($rawJson)) {
                $managedUsers = $rawJson | ConvertFrom-Json
                foreach ($entry in $managedUsers) {
                    if ($null -eq $entry) { continue }

                    # Case-insensitive comparison on username
                    if ($entry.username -and ($entry.username -ieq $JumpCloudUserName)) {
                        $jumpCloudManaged = $true
                        break
                    }
                }
            }
        } catch {
            Write-ToLog -Message:("Validation: Failed to parse managedUsers.json: $($_.Exception.Message)")
        }
    }

    return [PSCustomObject]@{
        exists           = $exists
        jumpCloudCreated = $jumpCloudCreated
        jumpCloudManaged = $jumpCloudManaged
        admuCreated      = $admuCreated
    }
}