function Get-Memberships {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^S-\d-\d+-(\d+-){1,14}\d+$")]
        [System.String]
        $SID
    )

    $memberships = New-Object System.Collections.ArrayList

    Get-LocalGroup | ForEach-Object {
        $member = Get-LocalGroupMember -Group $_.Name -Member $SID -ErrorAction SilentlyContinue
        if ($null -ne $member) {
            $memberships.Add($_) | Out-Null
        }
    }

    return $memberships
}
