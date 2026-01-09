function Invoke-SystemAPI {
    param (
        [Parameter(Mandatory = $true)]
        [string]$jcApiKey,
        [Parameter(Mandatory = $false)]
        [string]$jcOrgID,
        [Parameter(Mandatory = $true)]
        [string]$systemId,
        [Parameter(Mandatory = $false)]
        [object]$Body,
        [Parameter(Mandatory = $false)]
        [string]$method = "PUT"
    )
    $uri = "$($global:JCUrl)/api/systems/$systemId"

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
            if ($Body) {
                $bodyContent = $Body | ConvertTo-Json
            } else {
                $bodyContent = $null
            }
            $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $Headers -Body $bodyContent
            $retry = $false
        } catch {
            if ($_.Exception.Message -like "*The remote name could not be resolved*") {
                $retryCount++
                Start-Sleep -Seconds 2
                # add to retry counter and continue loop
                $retry = $true
            } else {
                $ErrorMessage = $_.Exception.Message
                Write-ToLog "Failed to update system: $($ErrorMessage)" -Level Warning -Step "Invoke-SystemAPI"
                # exit the loop
                $retry = $false
                $success = $false
            }
        }
    } while ($retry -and $retryCount -lt $maxRetries)
    if ($retryCount -eq $maxRetries) {
        Write-ToLog "Failed to resolve 'console.jumpcloud.com' after $maxRetries attempts." -Level Warning -Step "Invoke-SystemAPI"
    }
    if ($response) {
        return $response
    }
}