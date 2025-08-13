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
        # save the ACLs to a file which should always be $filePath + AppData\Local\JumpCloudADMU
        $aclFilePath = Join-Path -Path $FilePath -ChildPath "AppData\Local\JumpCloudADMU\aclfile.txt"
        icacls "$($FilePath)\*" /save $aclFilePath /t /c /q
        # Grant the new user permissions with icacls:
        # icacls C:\users\georgecostanza\ /restore C:\aclfile.txt /substitute "*$($SourceSID)" "*$($TargetSID)"
        icacls $FilePath /restore $aclFilePath /substitute "*$($SourceSID)" "*$($TargetSID)" /t /c /q
        # set the owner the with icacls:
        icacls $FilePath /setowner "*$($TargetSID)" /t /c /q
        icacls $FilePath /grant "*$($TargetSID):(OI)(CI)F"
        # Create SecurityIdentifier objects
        $SourceSIDObj = New-Object System.Security.Principal.SecurityIdentifier($SourceSID)
        $TargetSIDObj = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)

        # Get NTAccount names for logging and ACLs
        $SourceAccount = $SourceSIDObj.Translate([System.Security.Principal.NTAccount]).Value
        $TargetAccount = $TargetSIDObj.Translate([System.Security.Principal.NTAccount]).Value

        # Use icacls to find files/folders with explicit (non-inherited) ACLs
        # $icaclsOutput = icacls $FilePath /T /C /Q 2>&1
        # $explicitItems = @()
        # foreach ($line in $icaclsOutput) {
        #     # Each file/folder path is followed by its ACEs. If any ACE does not contain (I), it's explicit.
        #     if ($line -match '^(.*):') {
        #         $currentPath = $Matches[1]
        #         # Look ahead for ACEs
        #         if ($line -match ':.*\((?!I)') {
        #             $explicitItems += $currentPath
        #         }
        #     }
        # }
        # foreach ($itemPath in $explicitItems) {
        #     try {
        #         $acl = Get-Acl -Path $itemPath
        #         if ($null -eq $acl) { continue }
        #         # Change owner if SourceSID is current owner
        #         if (($acl.Owner -ne $TargetAccount) -and ($acl.Owner -eq $SourceAccount)) {
        #             $acl.SetOwner($TargetSIDObj)
        #             Set-Acl -Path $itemPath -AclObject $acl
        #         }
        #         # Copy SourceSID permissions to TargetSID only if not already present
        #         $aclChanged = $false
        #         foreach ($access in $acl.Access) {
        #             if ($access.IdentityReference -eq $SourceAccount) {
        #                 $perm = $access.FileSystemRights
        #                 $inheritance = $access.InheritanceFlags
        #                 $propagation = $access.PropagationFlags
        #                 $type = $access.AccessControlType
        #                 $targetHasRule = $false
        #                 foreach ($targetAccess in $acl.Access) {
        #                     if (
        #                         $targetAccess.IdentityReference -eq $TargetAccount -and
        #                         $targetAccess.FileSystemRights -eq $perm -and
        #                         $targetAccess.InheritanceFlags -eq $inheritance -and
        #                         $targetAccess.PropagationFlags -eq $propagation -and
        #                         $targetAccess.AccessControlType -eq $type
        #                     ) {
        #                         $targetHasRule = $true
        #                         break
        #                     }
        #                 }
        #                 if (-not $targetHasRule) {
        #                     $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        #                         $TargetAccount, $perm, $inheritance, $propagation, $type
        #                     )
        #                     $acl.AddAccessRule($newRule)
        #                     $aclChanged = $true
        #                 }
        #             }
        #         }
        #         if ($aclChanged) {
        #             Set-Acl -Path $itemPath -AclObject $acl
        #         }
        #     } catch {
        #         Write-ToLog "Failed to update $($itemPath) - $($_.Exception.Message)"
        #     }
        # }
    }
    end {

    }

}