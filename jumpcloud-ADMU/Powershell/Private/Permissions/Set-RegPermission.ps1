function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory = $false)]
        [scriptblock]$progressCallback
    )

    # Create SecurityIdentifier objects
    $SourceSIDObj = New-Object System.Security.Principal.SecurityIdentifier($SourceSID)
    $TargetSIDObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)

    # Get NTAccount names for logging and ACLs
    $SourceAccountTranslated = $false
    $TargetAccountTranslated = $false

    try {
        $SourceAccount = $SourceSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $SourceAccountTranslated = $true
    } catch {
        Write-ToLog "Warning: Could not translate SourceSID $SourceSID to NTAccount. Using SID string instead."
        $SourceAccount = $SourceSID
    }
    try {
        $TargetAccount = $TargetSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $TargetAccountTranslated = $true
    } catch {
        Write-ToLog "Warning: Could not translate TargetSID $TargetSID to NTAccount. Using SID string instead."
        $TargetAccount = $TargetSID
    }

    # Prepare icacls-compatible account identifiers (SIDs need * prefix)
    $SourceAccountIcacls = if ($SourceAccountTranslated) { $SourceAccount } else { "*$SourceAccount" }
    $TargetAccountIcacls = if ($TargetAccountTranslated) { $TargetAccount } else { "*$TargetAccount" }

    # Add the targetAccount to the ACL if it doesn't already exist
    $acl = Get-Acl -Path $FilePath
    $targetMember = $acl.Access | Where-Object { $_.IdentityReference -eq $TargetAccount }
    if (-not $targetMember) {
        $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $TargetAccount, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.AddAccessRule($newRule)
        Set-Acl -Path $FilePath -AclObject $acl
    }

    # Use icacls for bulk operations - much faster than PowerShell ACL cmdlets
    Write-ToLog "Starting permission migration using icacls for path: $FilePath"

    # Step 1: Grant target user full control inheritance on root folder
    Write-ToLog "Granting permissions to: $TargetAccountIcacls"
    $icaclsGrantResult = icacls.exe $FilePath /grant "${TargetAccountIcacls}:(OI)(CI)F" /T /C /Q

    if ($LASTEXITCODE -ne 0) {
        # Only log if there are non-filtered errors
        Write-ToLog "Warning: icacls grant operation had issues. Exit code: $LASTEXITCODE"
    } else {
        Write-ToLog "Successfully granted permissions to $TargetAccountIcacls"
    }

    # Step 2: Replace source user with target user in all ACLs (preserves existing permissions)
    # Write-ToLog "Substituting $SourceAccountIcacls with $TargetAccountIcacls"
    # $icaclsSubstResult = & icacls.exe $FilePath /substitute "$SourceAccountIcacls" "$TargetAccountIcacls" /T /C /Q 2>&1
    # if ($LASTEXITCODE -ne 0) {
    #     Write-ToLog "Warning: icacls substitute operation had issues. Exit code: $LASTEXITCODE"
    #     Write-ToLog "icacls substitute output: $($icaclsSubstResult -join ' ')"
    # } else {
    #     Write-ToLog "Successfully substituted $SourceAccountIcacls with $TargetAccountIcacls"
    # }

    # Step 3: Change ownership from source to target user
    Write-ToLog "Setting owner to $TargetAccountIcacls"
    $icaclsOwnerResult = icacls.exe $FilePath /setowner "$TargetAccountIcacls" /T /C /Q

    if ($LASTEXITCODE -ne 0) {
        # Only log if there are non-filtered errors
        Write-ToLog "Warning: icacls setowner operation had issues. Exit code: $LASTEXITCODE"
    } else {
        Write-ToLog "Successfully set owner to $TargetAccountIcacls"
    }

    # Provide progress feedback
    if ($ProgressCallback) {
        & $ProgressCallback 100 100  # Report completion
    }

    Write-ToLog "Permission migration completed for path: $FilePath"
}