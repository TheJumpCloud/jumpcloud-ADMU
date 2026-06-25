function Test-DATParentPermission {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DirectoryPath,

        [Parameter(Mandatory = $true)]
        [string]$UserSID
    )

    $requiredSIDs = @(
        'S-1-5-18',     # NT AUTHORITY\SYSTEM
        'S-1-5-32-544', # BUILTIN\Administrators
        $UserSID
    )

    $missingIdentities = [System.Collections.Generic.List[string]]::new()
    $insufficientRights = [System.Collections.Generic.List[PSCustomObject]]::new()

    function local:Get-IdentityName {
        param([string]$Sid)
        try {
            return (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            return $Sid
        }
    }

    function local:Test-DirectoryTraverseRights {
        param([System.Security.AccessControl.FileSystemRights]$Rights)

        $rightsValue = [int]$Rights
        $fullControl = [int][System.Security.AccessControl.FileSystemRights]::FullControl
        $modify = [int][System.Security.AccessControl.FileSystemRights]::Modify
        $readAndExecute = [int][System.Security.AccessControl.FileSystemRights]::ReadAndExecute
        $traverse = [int][System.Security.AccessControl.FileSystemRights]::Traverse
        $listDirectory = [int][System.Security.AccessControl.FileSystemRights]::ListDirectory
        $read = [int][System.Security.AccessControl.FileSystemRights]::Read

        if (($rightsValue -band $fullControl) -eq $fullControl) { return $true }
        if (($rightsValue -band $modify) -eq $modify) { return $true }
        if (($rightsValue -band $readAndExecute) -eq $readAndExecute) { return $true }
        if ((($rightsValue -band $traverse) -eq $traverse) -and ((($rightsValue -band $listDirectory) -eq $listDirectory) -or (($rightsValue -band $read) -eq $read))) {
            return $true
        }

        return $false
    }

    function local:Get-MissingTraverseRights {
        param([System.Security.AccessControl.FileSystemRights]$Rights)

        $missing = [System.Collections.Generic.List[string]]::new()
        if (-not (Test-DirectoryTraverseRights -Rights $Rights)) {
            $requiredRights = @(
                [System.Security.AccessControl.FileSystemRights]::Traverse,
                [System.Security.AccessControl.FileSystemRights]::ListDirectory,
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.FileSystemRights]::Read
            )
            foreach ($requiredRight in $requiredRights) {
                if (([int]$Rights -band [int]$requiredRight) -ne [int]$requiredRight) {
                    $missing.Add($requiredRight.ToString())
                }
            }
        }
        return $missing
    }

    $acl = Get-Acl -Path $DirectoryPath -ErrorAction SilentlyContinue
    if (-not $acl) {
        return [PSCustomObject]@{
            IsValid            = $false
            MissingIdentities  = @('Directory not accessible or does not exist')
            InsufficientRights = @()
        }
    }

    foreach ($sid in $requiredSIDs) {
        $identityName = Get-IdentityName -Sid $sid
        $allowRules = @()

        foreach ($rule in $acl.Access) {
            try {
                $ruleSid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                $ruleSid = $rule.IdentityReference.Value
            }

            if ($ruleSid -eq $sid -and $rule.AccessControlType -eq 'Allow') {
                $allowRules += $rule
            }
        }

        if ($allowRules.Count -eq 0) {
            $missingIdentities.Add($identityName)
            continue
        }

        $hasSufficientRights = $false
        foreach ($rule in $allowRules) {
            if (Test-DirectoryTraverseRights -Rights $rule.FileSystemRights) {
                $hasSufficientRights = $true
                break
            }
        }

        if (-not $hasSufficientRights) {
            $bestRule = $allowRules | Sort-Object { [int]$_.FileSystemRights } -Descending | Select-Object -First 1
            $missingRights = Get-MissingTraverseRights -Rights $bestRule.FileSystemRights
            $insufficientRights.Add([PSCustomObject]@{
                    Identity      = $identityName
                    SID           = $sid
                    MissingRights = @($missingRights)
                })
        }
    }

    return [PSCustomObject]@{
        IsValid            = ($missingIdentities.Count -eq 0 -and $insufficientRights.Count -eq 0)
        MissingIdentities  = @($missingIdentities)
        InsufficientRights = @($insufficientRights)
    }
}
