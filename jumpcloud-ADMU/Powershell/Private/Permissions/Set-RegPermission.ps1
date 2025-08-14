function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath
    )

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
            if ($null -eq $acl) { continue }
            $aclChanged = $false
            # Change owner if SourceSID is current owner
            if (($acl.Owner -ne $TargetAccount) -and ($acl.Owner -eq $SourceAccount)) {
                $acl.SetOwner($TargetSIDObj)
                $aclChanged = $true
            }
            # Copy SourceSID permissions to TargetSID
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -eq $SourceAccount) {
                    $perm = $access.FileSystemRights
                    $inheritance = $access.InheritanceFlags
                    $propagation = $access.PropagationFlags
                    $type = $access.AccessControlType
                    $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $TargetAccount, $perm, $inheritance, $propagation, $type
                    )
                    $acl.AddAccessRule($newRule)
                    $aclChanged = $true
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