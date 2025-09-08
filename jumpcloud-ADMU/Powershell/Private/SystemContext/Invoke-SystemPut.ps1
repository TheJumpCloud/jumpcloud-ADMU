function Invoke-SystemPut {
    param (
        [Parameter(Mandatory = $true)]
        [string]$jcApiKey,
        [Parameter(Mandatory = $false)]
        [string]$jcOrgID,
        [Parameter(Mandatory = $true)]
        [string]$systemId,
        [Parameter(Mandatory = $true)]
        [object]$Body
    )
    $uri = "https://console.jumpcloud.com/api/systems/$systemId"

    $Headers = @{
        'Accept'       = 'application/json';
        'Content-Type' = 'application/json';
        'x-api-key'    = $jcApiKey;
    }
    if ($jcOrgID) {
        $Headers['x-org-id'] = $jcOrgID;
    }
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $Headers -Body ($Body | ConvertTo-Json)
    } catch {
        Write-ToLog "Failed to update system. Status: $($_.Exception.Response.StatusCode.value__) - $($_.Exception.Response.StatusDescription)" -Level Error
    }
}
