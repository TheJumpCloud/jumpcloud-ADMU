function Set-RegPermission {
    param (
        [Parameter(Mandatory)]
        [string]$SourceSID,
        [Parameter(Mandatory)]
        [string]$TargetSID,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter()]
        [string]$ACLOutputPath = "AppData\Local\JumpCloudADMU\"
    )
    begin {
        # Get the user names from the SIDs
        try {
            $sourceUser = (New-Object System.Security.Principal.SecurityIdentifier $SourceSid).Translate([System.Security.Principal.NTAccount]).Value
            $targetUser = (New-Object System.Security.Principal.SecurityIdentifier $TargetSid).Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            Write-Error "Failed to translate SIDs to user names. Error: $_"
        }

        write-host "SOURCEUSER: $sourceUser"
        write-host "TARGETUSER: $targetUser"
        # save the ACLs to a file, will default to $filePath + AppData\Local\JumpCloudADMU if not specified
        # test that the output path exists, if not create it
        write-host "Setting outputPath with $filePath and $ACLOutputPath"
        $outputPath = Join-Path -Path $FilePath -ChildPath $ACLOutputPath
        if (-not (Test-Path -Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath | Out-Null
        }
        # determine if the $filePath has a member of $targetUser
        $acl = Get-Acl $FilePath
        foreach ($access in $acl.Access) {
            Write-Host "Access: $($access.IdentityReference) - $($access.FileSystemRights) - $($access.AccessControlType)"
            if ($access.IdentityReference -eq $sourceUser) {
                $replace = $true
                write-host "Found source user in ACL, will replace permissions."
                break
            }
        }
        # $targetMember = $acl.Access | Where-Object { $_.IdentityReference -eq $sourceUser }
        # write-host "Current member: $($targetMember.IdentityReference)"
        # if ($targetMember) {
        #     $replace = $false
        # } else {
        #     $replace = $true
        # }

    }
    process {
        switch ($replace) {
            $true {
                # for the root object $filePath, add an ACL entry for the target SID
                $acl = Get-Acl -Path $FilePath
                $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $targetUser, "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
                )
                $acl.AddAccessRule($newRule)
                Set-Acl -Path $FilePath -AclObject $acl
                # create the full output path with filename:
                $aclFilePath = Join-Path -Path $outputPath -ChildPath "aclfile.txt"
                # save the ACLs to a file
                icacls "$($FilePath)\*" /save $aclFilePath /t /c /q 2>&1 | out-null
                # replace the SourceSID with TargetSID in the found files
                icacls $FilePath /restore $aclFilePath /substitute "*$($SourceSID)" "*$($TargetSID)" /t /c /q 2>&1 | out-null
                # set the owner the with icacls:
                $childItems = Get-ChildItem -Path $FilePath -Force
                foreach ($item in $childItems) {
                    $FilePath = $item.FullName
                    icacls $FilePath /setowner "*$($TargetSID)" /t /c /q 2>&1 | out-null
                }
                # icacls $FilePath /setowner "*$($TargetSID)" /t /c /q
                # Grant the new user permissions with icacls:
                icacls $FilePath /grant "*$($TargetSID):(OI)(CI)F" 2>&1 /t /c /q | out-null
            }
            $false {
                Write-Host "No changes made to permissions as the file is not accessible by the source user."
            }
        }
    }
    end {

    }
}