function Invoke-SystemPut {
    <#
    .SYNOPSIS
    Updates a system's description using the JumpCloud API.

    .DESCRIPTION
    This function performs a PUT request to the JumpCloud API to update the description of a device.
    It is intended to be used when the SystemContext API is not available or cannot be validated.

    .PARAMETER ApiKey
    The JumpCloud API key for authentication.

    .PARAMETER Body
    A hashtable or JSON object containing the properties to update. For example: @{ description = "New description" }

    .EXAMPLE
    PS C:\> $updateBody = @{ description = "Updated via ADMU" }
    PS C:\> Invoke-SystemPut -ApiKey "jc_api_key_xxxxxxxxxx" -Body $updateBody -systemId "system_id_here"
    # This will update the description of the local system in JumpCloud.
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$JumpCloudAPIKey,
        [Parameter(Mandatory = $false)]
        [string]$JumpCloudOrgID,
        [Parameter(Mandatory = $true)]
        [string]$systemId,
        [Parameter(Mandatory = $true)]
        [object]$Body
    )
    $uri = "https://console.jumpcloud.com/api/systems/$systemId"

    $Headers = @{
        'Accept'       = 'application/json';
        'Content-Type' = 'application/json';
        'x-api-key'    = $JumpCloudApiKey;
    }
    if ($JumpCloudOrgID) {
        $Headers['x-org-id'] = $JumpCloudOrgID;
    }
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $Headers -Body ($Body | ConvertTo-Json)
    } catch {
        Write-ToLog "Failed to update system. Status: $($_.Exception.Response.StatusCode.value__) - $($_.Exception.Response.StatusDescription)" -Level Error
    }
}
