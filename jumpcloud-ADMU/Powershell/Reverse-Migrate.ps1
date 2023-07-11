Function Undo-Migration {
    #parameter is SID of the user to undo the migration for
    param (
        [Parameter(ParameterSetName = 'cmd', Mandatory = $true)][string]$SelectedUserSid
    )
    # Get the SID of the user to undo the migration for
    $CurrentProfileImagePath = Get-ItemPropertyValue -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $SelectedUserSID) -Name 'ProfileImagePath'

    $currentRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)"

    if (-Not (Test-Path -Path $currentRegistryPath)) {
        Write-toLog "Previous SID or Profile Path does not exist in the registry."
        exit
    }

    # Get the backup NTUser.dat sid and profile path
    $registryBackupPaths = @(
        "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat",
        "$($CurrentProfileImagePath)\NTUser.dat"
    )

    foreach ($registryBackupPath in $registryBackupPaths) {
        if (-Not (Test-Path -Path $registryBackupPath)) {
            Write-toLog "Registry backup file '$registryBackupPath' does not exist."
            exit
        } else {
            Write-toLog "Found registry backup file '$registryBackupPath'."
        }
    }

    try {
        Write-toLog "Loading registry backup hive"
        reg load HKU\TempHive $CurrentProfileImagePath\NTUser.dat
    }
    catch {
        Write-toLog "Failed to load registry backup hive"
        exit
    }


    # Validate that the device is connected to a domain
    #TODO Check domain
    $domain = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Domain
    if ($null -eq $domain) {
        Write-toLog "This device is not connected to a domain. Please connect to a domain and try again."
        return
    }



    ###### Reverse the migration

    # Get the profile path from the registry
    $backupProfileImagePath = Get-ItemPropertyValue -Path 'Registry::HKEY_USERS\TempHive\Software\JCADMU' -Name 'previousProfilePath'
    $backupProfileImageSid = Get-ItemPropertyValue -Path 'Registry::HKEY_USERS\TempHive\Software\JCADMU' -Name 'previousSID'
    if ($null -eq $backupProfileImagePath -or $null -eq $backupProfileImageSid) {
        Write-ToLog "Previous SID or Profile Path does not exist in the registry."
        exit
    }
    # Get the old profile path from the registry
    $oldProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath'

    # Set the backup registry profileImagePath to the current profile path
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "Sid" -Value $backupProfileImageSid
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name "ProfileImagePath" -Value $oldProfileImagePath # Put a null value to the selected profile that's going to be reversed
    # Validate if the profile path has been changed
    $newProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SelectedUserSid)" -Name 'ProfileImagePath'
    if ($newProfileImagePath -eq $oldProfileImagePath) {
        Write-toLog "Old Profile path $oldProfileImagePath has been set"
    } else {
        Write-toLog "Profile path has not been changed."
        return
    }
    # This is going to be the new profile that's going to be used
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name "ProfileImagePath" -Value $backupProfileImagePath
    # Validate if the profile path has been changed
    $newProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($backupProfileImageSid)" -Name 'ProfileImagePath'
    if ($newProfileImagePath -eq $backupProfileImagePath) {
        Write-toLog "New Profile path $backupProfileImagePath has been set"
    } else {
        Write-toLog "Profile path has not been changed."
        return
    }
    reg unload HKU\TempHive
    # Get the selected user ProfileImagePath
    #$selectedProfileImagePath = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($selectedUserSid)" -Name 'ProfileImagePath'

    ##### Rename the NTUser.dat files in User's profile
    $renameDate = Get-Date -UFormat "%Y-%m-%d-%H%M%S"
    Rename-Item -Path "$($CurrentProfileImagePath)\NTUser.dat" -NewName "NTUser_old_$renameDate.dat"
    # Find and rename C:\Users\kentest\NTUser_Original_2021-03-24-142959.dat to NTUser.dat regex
    $pattern = "NTUser_Original_*"
    $replacement = "NTUser.dat"

    $NTbackupFile = Get-ChildItem -Path $CurrentProfileImagePath -Filter $pattern -Force

    # TODO: Polish this
    $NTbackupFile | Rename-Item -NewName { $_.name -replace $NTbackupFile.Name, $replacement }

    ##### Rename the UsrClass.dat files in User's profile
    Rename-Item -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat" -NewName "UsrClass_old_$($renameDate).dat"

    $pattern = "UsrClass_Original_*"
    $replacement = "UsrClass.dat"
    $UsrbackupFile = Get-ChildItem -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\" -Filter $pattern -Force
    # Validate if file exists
    if ($null -eq $UsrbackupFile) {
        Write-toLog "File does not exist"
        return
    } else {
        Write-toLog "Found Profile backup file '$UsrbackupFile'."
    }

    $UsrbackupFile | Rename-Item -NewName { $_.name -replace $UsrbackupFile.Name, $replacement }
    # Validate if UsrClass.dat file exists
    if (-Not (Test-Path -Path "$($CurrentProfileImagePath)\AppData\Local\Microsoft\Windows\UsrClass.dat")) {
        Write-toLog "UsrClass.dat file does not exist"
        return
    } else {
        Write-toLog "Found UsrClass.dat file."
    }

    return $true

}