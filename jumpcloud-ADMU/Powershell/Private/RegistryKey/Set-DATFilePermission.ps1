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
        $aclUser = "$($Env:ComputerName)\$Username"
        $requiredIdentities = @(
            "NT AUTHORITY\SYSTEM",
            "BUILTIN\Administrators",
            "$aclUser"
        )
    }

    process {
        try {
            $acl = Get-Acl -Path $Path
            $isProtected = $acl.AreAccessRulesProtected
            $modified = $false

            foreach ($identity in $requiredIdentities) {
                $existingRules = @($acl.Access | Where-Object { $_.IdentityReference -eq $identity })
                $hasValidAllow = $false

                foreach ($rule in $existingRules) {
                    if ($rule.AccessControlType -eq 'Deny') {
                        $acl.RemoveAccessRule($rule) | Out-Null
                        $modified = $true
                        Write-ToLog -Message "Set-DATFilePermission: Removed Deny rule for $identity on $Path" -Level Verbose
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
                        Write-ToLog -Message "Set-DATFilePermission: Removed insufficient Allow rule for $identity on $Path" -Level Verbose
                    }
                }

                if (-not $hasValidAllow) {
                    if ($Type -eq 'registry') {
                        $newRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                            $identity, 'FullControl', 'Allow'
                        )
                    } else {
                        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $identity, 'FullControl', 'Allow'
                        )
                    }
                    $acl.SetAccessRule($newRule)
                    $modified = $true
                    Write-ToLog -Message "Set-DATFilePermission: Added Allow FullControl for $identity on $Path" -Level Verbose
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
