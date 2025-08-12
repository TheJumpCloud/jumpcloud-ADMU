function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    begin {


    }
    process {
        # Grant the new user permissions with icacls::
        icacls $FilePath /grant ${TargetSID}:(OI)(CI)F /T
        # Create SecurityIdentifier objects
        $SourceSIDObj = New-Object System.Security.Principal.SecurityIdentifier($SourceSID)
        $TargetSIDObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)

        # Get NTAccount names for logging and ACLs
        $SourceAccount = $SourceSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $TargetAccount = $TargetSIDObj.Translate([System.Security.Principal.NTAccount]).Value

        # Get all files and folders recursively, including hidden/system
        $items = Get-ChildItem -Path $FilePath -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            try {
                $acl = Get-Acl -Path $item.FullName

                if ($null -eq $acl) {
                    continue
                }

                # Change owner if SourceSID is current owner
                if (($acl.Owner -ne $TargetAccount) -and ($acl.Owner -eq $SourceAccount)) {
                    $acl.SetOwner($TargetSIDObj)
                    Set-Acl -Path $item.FullName -AclObject $acl
                }


                # Copy SourceSID permissions to TargetSID only if not already present
                $aclChanged = $false
                foreach ($access in $acl.Access) {
                    if ($access.IdentityReference -eq $SourceAccount) {
                        $perm = $access.FileSystemRights
                        $inheritance = $access.InheritanceFlags
                        $propagation = $access.PropagationFlags
                        $type = $access.AccessControlType

                        $targetHasRule = $false
                        foreach ($targetAccess in $acl.Access) {
                            if (
                                $targetAccess.IdentityReference -eq $TargetAccount -and
                                $targetAccess.FileSystemRights -eq $perm -and
                                $targetAccess.InheritanceFlags -eq $inheritance -and
                                $targetAccess.PropagationFlags -eq $propagation -and
                                $targetAccess.AccessControlType -eq $type
                            ) {
                                $targetHasRule = $true
                                break
                            }
                        }
                        if (-not $targetHasRule) {
                            $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                $TargetAccount, $perm, $inheritance, $propagation, $type
                            )
                            $acl.AddAccessRule($newRule)
                            $aclChanged = $true
                        }
                    }
                }

                if ($aclChanged) {
                    Set-Acl -Path $item.FullName -AclObject $acl
                }
            } catch {
                if ($_.Exception.Message -notmatch "because it is null") {
                    Write-ToLog "Failed to update $($item.FullName): $($_.Exception.Message)"
                }
            }
        }
    }
    end {

    }

}