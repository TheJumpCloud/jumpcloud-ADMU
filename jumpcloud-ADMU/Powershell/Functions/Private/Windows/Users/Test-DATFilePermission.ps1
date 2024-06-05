# Function to validate if NTUser.dat has SYSTEM, Administrators, and the specified user as full control
function Test-DATFilePermission {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $path,
        [Parameter(Mandatory = $true)]
        [System.String]
        $username,
        [Parameter(Mandatory = $true)]
        [ValidateSet("registry", "ntfs")]
        [System.String]
        $type

    )
    begin {
        $aclUser = "$($Env:ComputerName)\$username"
        # ACL naming differs on registry/ ntfs file system, set the correct type
        switch ($type) {
            'registry' {
                $FilePermissionType = 'RegistryRights'
            }
            'ntfs' {
                $FilePermissionType = 'FileSystemRights'
            }
        }
        # define empty list
        $permissionsHash = @{}
        # define required list to test
        $requiredAccess = @{
            "NT AUTHORITY\SYSTEM"    = @{
                name = "System"
            };
            "BUILTIN\Administrators" = @{
                name = "Administrators"
            };
            "$($aclUser)"            = @{
                name = "$username"
            }
        }
        # Get the path
        $ACL = Get-Acl $path
    }
    process {
        # Using AccessControlType to check if it's a deny rule instead of allow since, with NTFS permissions, even if a user/admin is denied, there will still be an allow rule for them and not null
        foreach ($requiredRule in $requiredAccess.keys) {
            # foreach ($requiredRule in $systemRule, $administratorsRule, $specifiedUserRule) {
            # write-ToLog "Begin testing: $($requiredRule)"
            $FileACLs = $acl.Access | Where-Object { $_.IdentityReference -eq "$($requiredRule)" }
            # write-ToLog "$($requiredRule) access count: $($FileACLs.Count)"
            foreach ($fileACL in $FileACLs) {
                $rulePermissions = [PSCustomObject]@{
                    access            = $FileACL.AccessControlType
                    permissionType    = $FileACL.$($FilePermissionType)
                    identityReference = $FileACL.IdentityReference
                    ValidPermissions  = $true
                }
                # There will sometimes be multiple FileACLs if an identity is denied access, in which case just break
                if ($FileACL.AccessControlType -contains 'Deny') {
                    $rulePermissions.ValidPermissions = $false
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                    break
                }
                # if fullControl access is not grated, just break
                if ($FileACL.$($FilePermissionType) -notcontains 'FullControl') {
                    $rulePermissions.ValidPermissions = $false
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                    break
                }
                # else record the access rule and assume it's valid
                if ("$($requiredAccess["$($requiredRule)"].name)" -notin $permissionsHash.Keys) {
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                }
            }
            # if the access is not explicitly granted, record the missing value so we can make use of it later
            if (-not $FileACLs) {
                $rulePermissions = [PSCustomObject]@{
                    access            = $null
                    permissionType    = $null
                    identityReference = $requiredRule
                    ValidPermissions  = $false
                }
                if ("$($requiredAccess["$($requiredRule)"].name)" -notin $permissionsHash.Keys) {
                    $permissionsHash.Add("$($requiredAccess["$($requiredRule)"].name)", $rulePermissions) | Out-Null
                }
            }
        }

    }
    end {
        # if the validPermission block contains any 'false' entries, return false + values, else return true + values
        if (($permissionsHash.Values.ValidPermissions -contains $false)) {
            return $false, $permissionsHash.Values
        } else {
            return $true, $permissionsHash.Values
        }
    }
}
