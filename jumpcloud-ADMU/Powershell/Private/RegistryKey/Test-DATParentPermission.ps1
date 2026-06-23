function Test-DATParentPermission {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath,

        [Parameter(Mandatory = $true)]
        [string]$UserSID
    )

    # SIDs for SYSTEM, Built-in Administrators, and the target user
    $requiredSIDs = @(
        'S-1-5-18',     # NT AUTHORITY\SYSTEM
        'S-1-5-32-544', # BUILTIN\Administrators
        $UserSID
    )

    $acl = Get-Acl -Path $DirectoryPath -ErrorAction SilentlyContinue
    if (-not $acl) {
        return $false
    }

    $isValid = $true

    foreach ($sid in $requiredSIDs) {
        $hasAccess = $false

        foreach ($rule in $acl.Access) {
            # Translate IdentityReference to a SID string.
            try {
                $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                # Fallback in case it's already a raw SID string or orphaned
                $ruleSid = $rule.IdentityReference.Value
            }

            # Check if the rule applies to our required SID and grants Allow access
            if ($ruleSid -eq $sid -and $rule.AccessControlType -eq 'Allow') {
                $hasAccess = $true
                break
            }
        }

        if (-not $hasAccess) {
            $isValid = $false
        }
    }

    return $isValid
}