function Get-mtpOrganization {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $apiKey,
        [Parameter()]
        [System.String]
        $orgID,
        [parameter()]
        [switch]
        $inputType
    )
    begin {
        $skip = 0
        $limit = 100
        $paginate = $true
        $Headers = @{
            'Content-Type' = 'application/json';
            'Accept'       = 'application/json';
            'x-api-key'    = "$($apiKey)";
        }
        $results = @()
        if ($orgID) {
            Write-ToLog -Message "OrgID specified, attempting to validate org..."
            $baseURl = "https://console.jumpcloud.com/api/organizations/$($orgID)"
            $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
            $Content = $Request.Content | ConvertFrom-Json
            $results += $Content
        } else {
            Write-ToLog -Message "No OrgID specified, attempting to search for valid orgs..."
            while ($paginate) {
                $baseUrl = "https://console.jumpcloud.com/api/organizations"
                $Request = Invoke-WebRequest -Uri "$($baseUrl)?limit=$($limit)&skip=$($skip)" -Method Get -Headers $Headers -UseBasicParsing
                $Content = $Request.Content | ConvertFrom-Json
                $results += $Content.results
                if ($Content.results.Count -eq $limit) {
                    $skip += $limit
                } else {
                    $paginate = $false
                }
            }
        }
    }
    process {
        # if there's only one org return found org, else prompt for selection
        if (($results.count -eq 1) -And ($($results._id))) {
            Write-ToLog -Message "API Key Validated`nOrgName: $($results.DisplayName)"
            $orgs = $results._id, $results.DisplayName
        } elseif (($results.count -gt 1)) {
            Write-ToLog -Message "Found $($results.count) orgs with the specifed API Key"
            # initial prompt for MTP selection
            switch ($inputType) {
                $true {
                    Write-ToLog -Message "Prompting for MTP Admin Selection"
                    $orgs = show-mtpSelection -Orgs $results
                    Write-ToLog -Message "API Key Validated`nOrgName: $($orgs[1])"
                }
                Default {
                    Write-ToLog -Message "API Key appears to be a MTP Admin Key. Please specify the JumpCloudOrgID Parameter and try again"
                    throw "API Key appears to be a MTP Admin Key. Please specify the JumpCloudOrgID Parameter and try again"
                }
            }
        } else {
            Write-ToLog -Message "No orgs matched provided API Key"
            $orgs = $false
        }

    }
    end {
        #returned org as an object [0]=id [1]=dispalyName
        return $orgs
    }
}
