function Test-APIKey {
    param (
        [string]$apiKey,
        [string]$OrgID
    )
    begin {
        try {
            # Ensure the config file actually exists before trying to read it
            $confPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            if (-not (Test-Path $confPath)) {
                throw "Configuration file not found at '$confPath'"
            }
            $config = get-content $confPath
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        } catch {
            throw "Failed to get systemKey from jcagent.conf. Reason: $($_.Exception.Message)"
        }
    }
    process {
        try {
            $headers = @{}
            $headers.Add("x-api-key", $apiKey)
            if ($OrgID) {
                $headers.Add("x-org-id", $OrgID)
            }
            $response = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systems/$systemKey" -Method GET -Headers $headers

            # If response id is eq to systemKey, the API key is valid
            if ($response.id -eq $systemKey) {
                Write-Host "API key is valid."
                return $true, $response.id
            } else {
                # This case is unlikely if the API call succeeds, but included for completeness
                Write-ToLog "API key is invalid. The returned ID did not match the systemKey." -Level Warn
                return $false
            }
        } catch {
            # Catch errors from Invoke-RestMethod (e.g., 401 Unauthorized)
            Write-ToLog "API call failed. The key is likely invalid or there was a network issue." -Level Warn
            Write-ToLog "Error details: $($_.Exception.Message)" -Level Warn
            return $false
        }


    }
}
