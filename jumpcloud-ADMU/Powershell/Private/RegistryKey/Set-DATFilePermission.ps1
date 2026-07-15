function Set-DATFilePermission {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,
        [Parameter(Mandatory = $true)]
        [System.String]
        $Username,
        [Parameter(Mandatory = $true)]
        [ValidateSet("registry", "ntfs")]
        [System.String]
        $Type
    )

    begin {
        $userSid = Convert-UserName -user "$($Env:ComputerName)\$Username"
        $requiredIdentities = @(
            'S-1-5-18',     # NT AUTHORITY\SYSTEM
            'S-1-5-32-544', # BUILTIN\Administrators
            $userSid
        )
    }

    process {
        try {
            $acl = Get-Acl -Path $Path
            $isProtected = $acl.AreAccessRulesProtected
            $modified = $false

            foreach ($identitySid in $requiredIdentities) {
                $existingRules = @($acl.Access | Where-Object {
                    try {
                        $ruleSid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch {
                        $ruleSid = $_.IdentityReference.Value
                    }
                    $ruleSid -eq $identitySid
                })
                $hasValidAllow = $false

                foreach ($rule in $existingRules) {
                    if ($rule.AccessControlType -eq 'Deny') {
                        $acl.RemoveAccessRule($rule) | Out-Null
                        $modified = $true
                        Write-ToLog -Message "Set-DATFilePermission: Removed Deny rule for $identitySid on $Path" -Level Verbose
                        continue
                    }

                    $rightsValid = if ($Type -eq 'registry') {
                        $rule.RegistryRights -contains 'FullControl'
                    } else {
                        $rule.FileSystemRights -contains 'FullControl'
                    }

                    if ($rightsValid) {
                        $hasValidAllow = $true
                    } else {
                        $acl.RemoveAccessRule($rule) | Out-Null
                        $modified = $true
                        Write-ToLog -Message "Set-DATFilePermission: Removed insufficient Allow rule for $identitySid on $Path" -Level Verbose
                    }
                }

                if (-not $hasValidAllow) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($identitySid)
                    if ($Type -eq 'registry') {
                        $newRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                            $sidObj, 'FullControl', 'Allow'
                        )
                    } else {
                        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $sidObj, 'FullControl', 'Allow'
                        )
                    }
                    $acl.SetAccessRule($newRule)
                    $modified = $true
                    Write-ToLog -Message "Set-DATFilePermission: Added Allow FullControl for $identitySid on $Path" -Level Verbose
                }
            }

            if ($modified) {
                $acl.SetAccessRuleProtection($isProtected, $false)
                Set-Acl -Path $Path -AclObject $acl
            }
        } catch {
            Write-ToLog -Message "Set-DATFilePermission: Failed to update permissions on $Path : $($_.Exception.Message)" -Level Warning
            return $false
        }

        $valid, $null = Test-DATFilePermission -Path $Path -Username $Username -Type $Type
        return $valid
    }
}
