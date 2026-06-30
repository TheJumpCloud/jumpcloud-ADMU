function Set-Memberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        $GroupSids,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]
        $SID
    )

    foreach ($groupSid in $GroupSids) {
        if ([string]::IsNullOrWhiteSpace($groupSid)) {
            continue
        }

        Add-LocalGroupMember -SID $groupSid -Member $SID -ErrorAction SilentlyContinue
    }
}
