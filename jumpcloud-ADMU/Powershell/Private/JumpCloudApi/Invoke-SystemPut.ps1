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
    $maxRetries = 3
    $retryCount = 0
    do {
        try {
            $response = Invoke-RestMethod -Uri $uri -Method Put -Headers $Headers -Body ($Body | ConvertTo-Json)
            $success = $true
        } catch {
            if ($_.Exception.Message -like "*The remote name could not be resolved*") {
                $retryCount++
                Start-Sleep -Seconds 2
            } else {
                Write-ToLog "Failed to update system: $($_.Exception.Message)" -Level Warning
            }
            $success = $false
        }
    } while (-not $success -and $retryCount -lt $maxRetries)
    if (-not $success) {
        Write-ToLog "Failed to resolve 'console.jumpcloud.com' after $maxRetries attempts." -Level Warn
    }
}
