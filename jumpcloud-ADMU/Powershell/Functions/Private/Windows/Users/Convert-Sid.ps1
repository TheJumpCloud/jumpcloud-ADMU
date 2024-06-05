function Convert-Sid {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $Sid
    )
    process {
        try {
            (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate( [System.Security.Principal.NTAccount]).Value
        } catch {
            return $Sid
        }
    }
}