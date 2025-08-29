function Test-APIKey {
    param (
        [string]$jumpCloudApiKey,
        [string]$JumpCloudOrgID
    )
    process {
        $headers = @{}
        $headers.Add("x-api-key", $jumpCloudApiKey)
        if ($JumpCloudOrgID) {
            $headers.Add("x-org-id", $JumpCloudOrgID)
        }
        $response = Invoke-RestMethod -Uri 'https://console.jumpcloud.com/api/systems?' -Method GET -Headers $headers
        $response.Count

        # If results > 0, the API key is valid
        if ($response.Count -ge 0) {
            return $true
        }
    }

}
