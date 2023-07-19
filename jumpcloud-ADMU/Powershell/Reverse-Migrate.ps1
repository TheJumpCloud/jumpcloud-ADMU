function Get-UserHiveFile {
# Get the SID of the user to undo the migration for
    #parameter is SID of the user to undo the migration for
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid
    )
    $CurrentProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'

    $currentRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)"

    if (-Not (Test-Path -Path $currentRegistryPath)) {
        Write-toLog "Previous SID or Profile Path does not exist in the registry. $($SelectedUserSid)"
        Throw "Previous SID or Profile Path does not exist in the registry"
    }
    # Get the backup NTUser.dat sid and profile path
    $registryBackupPaths = @(
        "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat",
        "$($CurrentProfileImagePath)\NTUser.dat"
    )

    foreach ($registryBackupPath in $registryBackupPaths) {
        if (-Not (Test-Path -Path $registryBackupPath)) {
            Write-toLog "Registry backup file '$registryBackupPath' does not exist." -Level "Error"
            throw "Registry backup file does not exist"
        } else {
            Write-toLog "Found registry backup file '$registryBackupPath'."
            return $true
        }
    }
}
function Get-Domain {
        $dsregcmdOutput = dsregcmd /status

        $properties = @{}

        $dsregcmdOutput | ForEach-Object {
            if ($_ -match '^([^:]+):\s+(.*)$') {
                $propertyName = $Matches[1].Trim()
                $propertyValue = $Matches[2].Trim()
                $properties[$propertyName] = $propertyValue
            }
        }
        if ($properties.AzureADJoined -eq "Yes") {
            Write-ToLog "Domain is joined to AzureAD"
            return $true
        } else {
            Write-ToLog "Domain is not joined to AzureAD"
            return $false
        }
}

function Update-NTUserDat {
    # Get the selected user ProfileImagePath
    #$selectedProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($selectedUserSid)" -Name 'ProfileImagePath'
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$CurrentProfileImagePath,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$backupProfileImageSid,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$backupProfileImagePath


    )
    process {
        ##### Rename the NTUser.dat files in User's profile
        $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
        Rename-Item -Path "$($CurrentProfileImagePath)\NTUser.dat" -NewName "NTUser_old_$renameDate.dat"
        # Validate if the rename was successful
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\NTUser_old_$renameDate.dat")) {
            Write-toLog "Failed to rename NTUser.dat to NTUser_old_$renameDate.dat" -Level "Error"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $backupProfileImagePath
            throw
        } else {
            Write-toLog "Renamed NTUser.dat to NTUser_old_$renameDate.dat"
        }
        # Find and rename C:\Users\kentest\NTUser_Original_2021-03-24-142959.dat to NTUser.dat regex
        $pattern = "NTUser_Original_*"
        $replacement = "NTUser.dat"
        #TODO: Check if only one file exists
        $NTbackupFile = Get-ChildItem -Path $CurrentProfileImagePath -Filter $pattern -Force
        if ([System.String]::IsNullOrEmpty($NTbackupFile) -or $NTbackupFile.Count -gt 1) {
            Write-toLog "Backup file not found or multiple found. Please manually check or rename the files and try again." -Level "Error"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $backupProfileImagePath

            throw
        } else {
            Write-toLog "Found Profile backup file '$NTbackupFile'."
        }
        $NTbackupFile | Rename-Item -NewName { $_.name -replace $NTbackupFile.Name, $replacement }
        # Validate if NTUser.dat file exists
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\NTUser.dat")) {
            Write-toLog "NTUser.dat file does not exist" -level "error"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $backupProfileImagePath
            throw
        } else {
            Write-toLog "Found NTUser.dat file."
            return $true
        }
    }
}

function Update-UsrClassDat {
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$CurrentProfileImagePath,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$backupProfileImageSid,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$backupProfileImagePath
    )
    process {
        $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
        ##### Rename the UsrClass.dat files in User's profile
        Rename-Item -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "UsrClass_old_$($renameDate).dat"
        # Validate if the rename was successful
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass_old_$($renameDate).dat")) {
            Write-toLog "Failed to rename UsrClass.dat to UsrClass_old_$($renameDate).dat" -Level "Error"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $backupProfileImagePath
            Throw
        } else {
            Write-toLog "Renamed UsrClass.dat to UsrClass_old_$($renameDate).dat"
        }

        $pattern = "UsrClass_Original_*"
        $replacement = "UsrClass.dat"
        $UsrbackupFile = Get-ChildItem -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\" -Filter $pattern -Force
        # Validate if file exists and only one file exists
        if ([System.String]::IsNullOrEmpty($UsrbackupFile) -or $UsrbackupFile.Count -gt 1) {
            Write-toLog "Backup file not found or multiple found. Please manually check or rename the files and try again." -Level "Error"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $backupProfileImagePath
            Throw
        } else {
            Write-toLog "Found Profile backup file '$UsrbackupFile'."
        }

        $UsrbackupFile | Rename-Item -NewName { $_.name -replace $UsrbackupFile.Name, $replacement }
        # Validate if UsrClass.dat file exists
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat")) {
            Write-toLog "UsrClass.dat file does not exist" -level "error"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $backupProfileImagePath
            Throw
        } else {
            Write-toLog "Found UsrClass.dat file."
            return $true
        }
    }

}
function Reverse-Migration {
    #parameter is SID of the user to undo the migration for
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid
    )

        $validateRegPath = Get-UserHiveFile -SelectedUserSid $SelectedUserSid # Exit if error
        # Get the old profile path from the registry
        $CurrentProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath'
        Write-ToLog "Current Profile Path: $CurrentProfileImagePath"
    $validateDomain = get-Domain # Exit if error
    if ($validateDomain) {
        Write-ToLog "This device is connected to a domain."
    } else {
        Write-ToLog "This device is not connected to a domain. Please connect to a domain and try again." -Level "Error"
        Throw "Domain not found"
    }
    if ($validateRegPath) {
        try {
            # Check if the registry hive is loaded
            $regHive = Get-Item -Path 'Registry::HKEY_USERS\TempHive'
            if ($regHive) {
                Write-toLog "Registry hive is already loaded. Unloading the hive."
                reg unload HKU\TempHive
            } else {
                Write-toLog "Loading registry backup hive"
                reg load HKU\TempHive $CurrentProfileImagePath\NTUser.dat
            }
        }
        catch {
            Write-toLog "Failed to load registry backup hive" -Level "Error"
            Throw "Failed to load registry backup hive"
        }
        $backupProfileImagePath = Get-ItemPropertyValue -Path 'Registry::HKEY_USERS\TempHive\Software\JCADMU' -Name 'previousProfilePath'
        $backupProfileImageSid = Get-ItemPropertyValue -Path 'Registry::HKEY_USERS\TempHive\Software\JCADMU' -Name 'previousSID'
        if ($null -eq $backupProfileImagePath -or $null -eq $backupProfileImageSid) {
            Write-ToLog "Previous SID or Profile Path does not exist in the registry."
            reg unload HKU\TempHive
            Throw "Previous SID or Profile Path does not exist in the registry."
        }
        $oldProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath'

        # Check if Get-UserHiveFile is successful


        ###### Reverse the migration
        # Get the profile path from the registry

        if ([System.String]::IsNullOrEmpty($oldProfileImagePath) ) {
            Write-Tolog "Old Profile path does not exist in the registry." -level "error"
            Throw "Old Profile path does not exist in the registry."
        } else {
            Write-toLog "Old Profile path found: $oldProfileImagePath"
            # Set the backup registry profileImagePath to the current profile path
            #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "Sid" -Value $backupProfileImageSid
            #TODO: Test
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name "ProfileImagePath" -Value $oldProfileImagePath # Put a null value to the selected profile that's going to be reversed
            # Validate if the profile path has been changed
            $newProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath'
            if ($newProfileImagePath -eq $oldProfileImagePath) {
                Write-toLog "Old Profile path $oldProfileImagePath has been set"
            } else {
                Write-toLog "Profile path has not been changed." -level "error"
                #Reverse change if error
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name "ProfileImagePath" -Value $CurrentProfileImagePath
                reg unload HKU\TempHive
                throw "Profile path has not been changed."
            }

            # This is going to be the new profile that's going to be used
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "ProfileImagePath" -Value $backupProfileImagePath
            # Validate if the profile path has been changed
            $newProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath'
            if ($newProfileImagePath -eq $backupProfileImagePath) {
                Write-toLog "New Profile path $backupProfileImagePath has been set"
            } else {
                Write-toLog "Profile path has not been changed."
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "ProfileImagePath" -Value $oldProfileImagePath
                reg unload HKU\TempHive
                Throw "Profile path has not been changed."
            }
        }
        reg unload HKU\TempHive

        $updateNTUserDat = Update-NTUserDat -CurrentProfileImagePath $CurrentProfileImagePath -backupProfileImageSid $backupProfileImageSid -backupProfileImagePath $backupProfileImagePath -SelectedUserSid $SelectedUserSid

        if ($updateUserDat) {
            Update-UsrClassDat -CurrentProfileImagePath $CurrentProfileImagePath -backupProfileImageSid $backupProfileImageSid -backupProfileImagePath $backupProfileImagePath -SelectedUserSid $SelectedUserSid
        }

    } else {
        Write-ToLog "Registry path does not exist." -Level "Error"
        Throw "Registry path does not exist."
    }

}
