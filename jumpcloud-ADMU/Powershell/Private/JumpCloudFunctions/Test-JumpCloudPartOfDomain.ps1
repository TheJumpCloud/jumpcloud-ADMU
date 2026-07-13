function Test-JumpCloudPartOfDomain {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    [OutputType([System.Nullable[System.Boolean]])]
    param (
        [Parameter(Mandatory = $false)]
        [object]$SystemResponse
    )

    if ($null -eq $SystemResponse) {
        return $null
    }

    $domainInfo = $SystemResponse.domainInfo
    if ($null -eq $domainInfo) {
        return $null
    }

    $partOfDomain = $domainInfo.PartOfDomain
    if ($null -eq $partOfDomain) {
        return $null
    }

    if ($partOfDomain -is [bool]) {
        return $partOfDomain
    }

    if ($partOfDomain -is [string]) {
        switch ($partOfDomain.ToLowerInvariant()) {
            'true' { return $true }
            'false' { return $false }
            default { return $null }
        }
    }

    try {
        return [bool]$partOfDomain
    } catch {
        return $null
    }
}
