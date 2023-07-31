
# TODO: Check if user is JumpCloud bound,
# TODO: Update homepath, check if current and backup registry path are not the same. Rename to Update HomePath
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

    # Get the backup NTUSER.DAT sid and profile path
    $registryBackupPaths = @(
        "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat",
        "$($CurrentProfileImagePath)\NTUSER.DAT"
    )

    foreach ($registryBackupPath in $registryBackupPaths) {
        if (-Not (Test-Path -Path $registryBackupPath)) {
            Write-toLog "Registry backup file '$registryBackupPath' does not exist"
            throw "Registry backup file does not exist"
        } else {
            Write-toLog "Found registry backup file '$registryBackupPath'."
            return $true, $CurrentProfileImagePath
        }
    }
}

function Validate-UpdatedHomepath {
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$backupProfileSID,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$currentProfileSID
    )

    # Validate if the profile path has been changed
    $currentProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($currentProfileSID)" -Name 'ProfileImagePath'
    $backupProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileSID)" -Name 'ProfileImagePath'
    if ($currentProfileImagePath -eq $backupProfileImagePath) {
        Write-toLog "Profile path is the same as the backup."
        return $false
    } else {
        Write-toLog "Profile path is different from the backup."
        return $true
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
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$oldProfileImagePath


    )
    process {
        Write-ToLog "Old Profile Path: $oldProfileImagePath"
        Write-ToLog "$($backupProfileImageSid)"
        ##### Rename the NTUSER.DAT files in User's profile
        $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
        Rename-Item -Path "$($CurrentProfileImagePath)\NTUSER.DAT" -NewName "NTUser_old_$renameDate.dat" #Test
        # Check if NTUSER.DAT file exists
        # Validate if the rename was successful
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\NTUser_old_$renameDate.dat")) {
            Write-toLog "Failed to rename NTUSER.DAT to NTUser_old_$renameDate.dat"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "ProfileImagePath" -Value $oldProfileImagePath
            throw
        } else {
            Write-toLog "Renamed NTUSER.DAT to NTUser_old_$renameDate.dat"
        }
        # Find and rename C:\Users\kentest\NTUser_Original_2021-03-24-142959.dat to NTUSER.DAT regex
        $pattern = "NTUser_Original_*"
        $replacement = "NTUSER.DAT"
        #TODO: Check if only one file exists
        $NTbackupFile = Get-ChildItem -Path $CurrentProfileImagePath -Filter $pattern -Force
        if ([System.String]::IsNullOrEmpty($NTbackupFile) -or $NTbackupFile.Count -gt 1) {
            Write-toLog "Backup file not found or multiple found. Please manually check or rename the files and try again."
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "ProfileImagePath" -Value $oldProfileImagePath

            throw
        } else {
            Write-toLog "Found Profile backup file '$NTbackupFile'."
        }
        $NTbackupFile | Rename-Item -NewName { $_.name -replace $NTbackupFile.Name, $replacement }
        # Validate if NTUSER.DAT file exists
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\NTUSER.DAT")) {
            Write-toLog "NTUSER.DAT file does not exist"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $oldProfileImagePath
            throw
        } else {
            Write-toLog "Found NTUSER.DAT file."
            return $true
        }
    }
}

function Update-UsrClassDat {
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$CurrentProfileImagePath,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$backupProfileImageSid,
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$oldProfileImagePath
    )
    process {
        $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
        ##### Rename the UsrClass.dat files in User's profile
        Rename-Item -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "UsrClass_old_$($renameDate).dat"
        # Validate if the rename was successful
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass_old_$($renameDate).dat")) {
            Write-toLog "Failed to rename UsrClass.dat to UsrClass_old_$($renameDate).dat"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $oldProfileImagePath
            Throw
        } else {
            Write-toLog "Renamed UsrClass.dat to UsrClass_old_$($renameDate).dat"
        }

        $pattern = "UsrClass_Original_*"
        $replacement = "UsrClass.dat"
        $UsrbackupFile = Get-ChildItem -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\" -Filter $pattern -Force
        # Validate if file exists and only one file exists
        if ([System.String]::IsNullOrEmpty($UsrbackupFile) -or $UsrbackupFile.Count -gt 1) {
            Write-toLog "Backup file not found or multiple found. Please manually check or rename the files and try again."
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $oldProfileImagePath
            Throw
        } else {
            Write-toLog "Found Profile backup file '$UsrbackupFile'."
        }

        $UsrbackupFile | Rename-Item -NewName { $_.name -replace $UsrbackupFile.Name, $replacement }
        # Validate if UsrClass.dat file exists
        if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat")) {
            Write-toLog "UsrClass.dat file does not exist"
            # Revert the migration
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath' -Value $CurrentProfileImagePath
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath' -Value $oldProfileImagePath
            Throw
        } else {
            Write-toLog "Found UsrClass.dat file."
            return $true
        }
    }

}
function Undo-Migration {
    #parameter is SID of the user to undo the migration for
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid
    )

    $validateRegPath, $CurrentProfileImagePath = Get-UserHiveFile -SelectedUserSid $SelectedUserSid # Exit if error

    $validateDomain = get-Domain # Exit if error
    if ($validateDomain) {
        Write-ToLog "This device is connected to a domain."
    } else {
        Write-ToLog "This device is not connected to a domain. Please connect to a domain and try again."
        Throw "Domain not found"
    }

    if ($validateRegPath) {
        try {
            # Check if the registry hive is loaded
            Write-toLog "Loading registry backup hive"
            reg load HKU\TempHive $CurrentProfileImagePath\NTUSER.DAT
        }
        catch {
            Write-toLog "Failed to load registry backup hive"
            Throw "Failed to load registry backup hive"
        }
        $backupProfileImagePath = Get-ItemPropertyValue -Path 'Registry::HKEY_USERS\TempHive\Software\JCADMU' -Name 'previousProfilePath'
        $backupProfileImageSid = Get-ItemPropertyValue -Path 'Registry::HKEY_USERS\TempHive\Software\JCADMU' -Name 'previousSID'
        if ($null -eq $backupProfileImagePath -or $null -eq $backupProfileImageSid) {
            Write-ToLog "Previous SID or Profile Path does not exist in the registry."
            reg unload HKU\TempHive
            Throw "Previous SID or Profile Path does not exist in the registry."
        }

        $validateHomePath = Validate-UpdatedHomepath -backupProfileSID $backupProfileImageSid -currentProfileSID $SelectedUserSid

        $renameProfileImagePath = $CurrentProfileImagePath
        Write-Tolog "Current Profile Path: $renameProfileImagePath"
        if ($validateHomePath) {
            Write-ToLog "Homepath is different from the backup. Updating homepath..."
            # Set the current profile path to the backup registry profile path

            $CurrentProfileImagePath = $backupProfileImagePath
            Write-Tolog "The current profile path is $CurrentProfileImagePath"
            # Rename the user folder $renameProfileImagePath to $CurrentProfileImagePath
        }

        $oldProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath'



        ###### Reverse the migration
        # Get the profile path from the registry

        if ([System.String]::IsNullOrEmpty($oldProfileImagePath) ) {
            Write-Tolog "Old Profile path does not exist in the registry."
            Throw "Old Profile path does not exist in the registry."
        } else {
            Write-toLog "Old Profile path found: $oldProfileImagePath"
            # Set the backup registry profileImagePath to the current profile path
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name "ProfileImagePath" -Value $oldProfileImagePath # Put a null value to the selected profile that's going to be reversed
            # Validate if the profile path has been changed
            $newProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath'
            if ($newProfileImagePath -eq $oldProfileImagePath) {
                Write-toLog "Old Profile path $oldProfileImagePath has been set"
            } else {
                Write-toLog "Profile path has not been changed."
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
        Write-Tolog "Unloading registry backup hive"
        reg unload HKU\TempHive
        Write-Tolog "$($oldProfileImagePath)"
        $updateNTUserDat = Update-NTUserDat -CurrentProfileImagePath $renameProfileImagePath -backupProfileImageSid $backupProfileImageSid -oldProfileImagePath $oldProfileImagePath -SelectedUserSid $SelectedUserSid
        if ($updateUserDat) {
            $updateUsrClassDat = Update-UsrClassDat -CurrentProfileImagePath $renameProfileImagePath -backupProfileImageSid $backupProfileImageSid -oldProfileImagePath $oldProfileImagePath -SelectedUserSid $SelectedUserSid
        }
        if ($updateUsrClassDat) {
            Write-Tolog "Successfully updated NTUSER.DAT and UsrClass.dat files."
            if ($validateHomePath) {
                Write-Tolog "Renaming user folder..."
                Rename-Item -Path $renameProfileImagePath -NewName $CurrentProfileImagePath -Force

            }
        }
    } else {
        Write-ToLog "Registry path does not exist."
        Throw "Registry path does not exist."
    }

}
