function Test-ApiKey {
    [CmdletBinding()]
    param (
        # This parameter now accepts multiple values from the pipeline
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$jcApiKey,
        # This parameter is optional and applies to all tests
        [Parameter(Mandatory = $false)]
        [string]$jcOrgId
    )

    begin {
        # Initialize a list to hold the results for each API key.
        # A generic list is more performant than a standard PowerShell array for this.
        $resultObject = [PSCustomObject]@{
            IsValid = $false
            ID      = $null
        }

        # Perform one-time setup that applies to all items.
        try {
            $confPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf'
            if (-not (Test-Path $confPath)) {
                Write-ToLog "Configuration file not found at '$confPath'." -Level Verbose -Step "Test-ApiKey"
            }
            $config = Get-Content $confPath
            $regex = 'systemKey\":\"(\w+)\"'
            $systemKey = [regex]::Match($config, $regex).Groups[1].Value

            if (-not $systemKey) {
                Write-ToLog "Could not find a systemKey in the configuration file." -level Error -Step "Test-ApiKey"
            }
        } catch {
            # If setup fails, the whole command fails. This is a terminating error.
            Write-ToLog "Failed to initialize function. Reason: $($_.Exception.Message)" -level Error -Step "Test-ApiKey"
        }
    }

    process {
        try {
            $headers = @{}
            $headers.Add("x-api-key", $jcApiKey)
            if ($jcOrgId) {
                $headers.Add("x-org-id", $jcOrgId)
            }
            $response = Invoke-RestMethod -Uri "$($global:JCUrl)/api/systems/$systemKey" -Method GET -Headers $headers # No need to set the region here for JCUrl; Should be set globally when the we test the API key in the beginning

            # Create a simplified result object.
            if ($response.id -eq $systemKey) {
                # SUCCESS: Key is valid and matches.
                $resultObject.IsValid = $true
                $resultObject.ID = $response.id
            } else {
                # FAILURE: Key is valid, but for a different system.
                $resultObject.IsValid = $false
                $resultObject.ID = $response.id
            }
        } catch {
            # FAILURE: The API call failed (e.g., 401 Unauthorized).
            $resultObject.IsValid = $false
            $resultObject.ID = $null
        }
    }

    end {
        # Return the entire collection of simplified results.
        return $resultObject
    }
}
