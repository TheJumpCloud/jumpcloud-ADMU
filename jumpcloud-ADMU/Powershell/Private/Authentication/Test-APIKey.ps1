function Test-ApiKey {
    [CmdletBinding()]
    param (
        # This parameter now accepts multiple values from the pipeline
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$jcApiKey,

        # This parameter is optional and applies to all tests
        [string]$jcOrgId
    )

    begin {
        # Initialize a list to hold the results for each API key.
        # A generic list is more performant than a standard PowerShell array for this.
        $results = [System.Collections.Generic.List[object]]::new()

        # Perform one-time setup that applies to all items.
        try {
            $confPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            if (-not (Test-Path $confPath)) {
                Write-ToLog "Configuration file not found at '$confPath'."
            }
            $config = Get-Content $confPath
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value

            if (-not $systemKey) {
                Write-ToLog "Could not find a systemKey in the configuration file." -level Error
            }
        } catch {
            # If setup fails, the whole command fails. This is a terminating error.
            Write-ToLog "Failed to initialize function. Reason: $($_.Exception.Message)" -level Error
        }
    }

    process {
        try {
            $headers = @{}
            $headers.Add("x-api-key", $jcApiKey)
            if ($jcOrgId) {
                $headers.Add("x-org-id", $jcOrgId)
            }
            $response = Invoke-RestMethod -Uri "https://console.jumpcloud.com/api/systems/$systemKey" -Method GET -Headers $headers

            # Create a simplified result object.
            if ($response.id -eq $systemKey) {
                # SUCCESS: Key is valid and matches.
                $resultObject = [PSCustomObject]@{
                    IsValid = $true
                    ID      = $response.id
                }
            } else {
                # FAILURE: Key is valid, but for a different system.
                $resultObject = [PSCustomObject]@{
                    IsValid = $false
                    ID      = $response.id
                }
            }
        } catch {
            # FAILURE: The API call failed (e.g., 401 Unauthorized).
            $resultObject = [PSCustomObject]@{
                IsValid = $false
                ID      = $null
            }
        }

        # Add the result for this key to the master list.
        $results.Add($resultObject)
    }

    end {
        # Return the entire collection of simplified results.
        return $results
    }
}