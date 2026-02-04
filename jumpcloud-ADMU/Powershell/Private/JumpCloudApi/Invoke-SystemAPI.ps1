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
    # region Attribute Mapping
    # Check if this is a PUT request containing 'attributes'
    if ($method -eq 'PUT' -and $Body -and $Body.ContainsKey('attributes')) {

        # Fetch current system to get existing attributes
        try {
            $currentSystem = Invoke-RestMethod -Uri $uri -Method 'GET' -Headers $Headers
            $currentAttributes = $currentSystem.attributes
        } catch {
            Write-ToLog "Attribute Merge Failed: Could not retrieve current system state. $($_.Exception.Message)" -Level 'Error'
            return
        }

        $incomingAttributes = $Body.attributes
        if ($incomingAttributes -is [string]) {
            # Handle case where user passed ConvertTo-Json string
            try {
                $incomingAttributes = $incomingAttributes | ConvertFrom-Json
            } catch {
                Write-ToLog "Failed to parse attributes JSON string." -Level 'Error'
            }
        }

        # Start with existing attributes (or empty array if none exist)
        $mergedAttributes = @()
        if ($null -ne $currentAttributes) {
            foreach ($attr in $currentAttributes) {
                $mergedAttributes += $attr
            }
        }

        # Merge
        $properties = if ($incomingAttributes -is [hashtable]) { $incomingAttributes.Keys } else { $incomingAttributes.PSObject.Properties.Name }

        foreach ($key in $properties) {
            $newValue = if ($incomingAttributes -is [hashtable]) { $incomingAttributes[$key] } else { $incomingAttributes.$key }

            $existingAttr = $mergedAttributes | Where-Object { $_.name -eq $key }

            if ($null -eq $newValue) {
                # Value is null, Remove the attribute
                if ($existingAttr) {
                    $mergedAttributes = @($mergedAttributes | Where-Object { $_.name -ne $key })
                }
            } elseif ($existingAttr) {
                # Exists -> Update value
                $existingAttr.value = [string]$newValue
            } else {
                # New -> Add new object
                $newAttr = @{
                    name  = $key
                    value = [string]$newValue
                }
                $mergedAttributes += $newAttr
            }
        }

        # Update the Body with the newly merged array
        $Body['attributes'] = $mergedAttributes
    }
    # endRegion Attribute Mapping


    $maxRetries = 3
    $retryCount = 0
    do {
        try {
            if ($Body) {
                $bodyContent = $Body | ConvertTo-Json -Depth 10 -Compress
            } else {
                $bodyContent = $null
            }
            $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $Headers -Body $bodyContent | Out-Null
            $retry = $false
        } catch {
            if ($_.Exception.Message -like "*The remote name could not be resolved*") {
                $retryCount++
                Start-Sleep -Seconds 2
                $retry = $true
            } else {
                $ErrorMessage = $_.Exception.Message
                Write-ToLog "Failed to update system: $($ErrorMessage)" -Level Warning -Step "Invoke-SystemAPI"
                # exit the loop
                $retry = $false
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