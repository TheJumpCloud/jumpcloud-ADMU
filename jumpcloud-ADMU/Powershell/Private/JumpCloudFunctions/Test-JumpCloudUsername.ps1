function Test-JumpCloudUsername {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [OutputType([System.Object[]])]
    param (
        [Parameter()]
        [System.String]
        $JumpCloudApiKey,
        [Parameter()]
        [System.String]
        $JumpCloudOrgID,
        [Parameter()]
        [System.String]
        $Username,
        [Parameter()]
        [System.Boolean]
        $prompt = $false
    )
    begin {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Headers = @{
            'Accept'       = 'application/json';
            'Content-Type' = 'application/json';
            'x-api-key'    = $JumpCloudApiKey;
            'x-org-id'     = $JumpCloudOrgID;
        }

        $Form = @{
            "filter" = @{
                'and' = @(
                    @{'username' = @{'$regex' = "(?i)(`^$($Username)`$)" } }
                )
            }
            "fields" = "username , systemUsername"
        }
        $Body = $Form | ConvertTo-Json -Depth 4
    }
    process {
        $regions = @("US", "EU", "IN")
        $found = $false
        foreach ($region in $regions) {
            Set-JcUrl -Region $region
            try {
                $baseUrl = "$($global:JCUrl)/api/search/systemusers"
                $Response = Invoke-WebRequest -Method 'Post' -Uri $baseUrl -Headers $Headers -Body $Body -UseBasicParsing
                $Results = $Response.Content | ConvertFrom-Json
                $StatusCode = $Response.StatusCode
                $found = $true
                break;
            } catch {
                continue;
            }
        }
        if (-not $found) {
            throw "Failed to connect to JumpCloud API endpoints. Please verify network connectivity and that the provided API Key and OrgID are valid. Global URI: $($global:JCUrl)"
        }
    }
    end {
        # Search User should return 200 success
        if ($StatusCode -ne 200) {
            Write-ToLog -Message "JumpCloud username could not be found" -Level Verbose -Step "Test-JumpCloudUsername"
            return $false, $null, $null
        }
        if ($Results.totalCount -eq 1 -and $($Results.results[0].username) -eq $Username) {
            # write-host $Results.results[0]._id
            Write-ToLog -Message "Identified JumpCloud User`nUsername: $($Results.results[0].username)`nID: $($Results.results[0]._id)" -Level Verbose -Step "Test-JumpCloudUsername"
            if ($Results.results[0].SystemUsername) {
                Write-ToLog -Message "JumpCloud User have a Local Account User set: $($Results.results[0].SystemUsername)" -Level Verbose -Step "Test-JumpCloudUsername"
                return $true, $Results.results[0]._id, $Results.results[0].SystemUsername
            } else {
                return $true, $Results.results[0]._id, $null
            }


        } else {
            if ($prompt) {
                $message += "$Username is not a valid JumpCloud User`nPlease enter a valid JumpCloud Username"
                $wshell = New-Object -ComObject Wscript.Shell
                $var = $wshell.Popup("$message", 0, "ADMU Status", 0x0 + 0x40)
            }
            return $false, $null, $null
        }
    }
}