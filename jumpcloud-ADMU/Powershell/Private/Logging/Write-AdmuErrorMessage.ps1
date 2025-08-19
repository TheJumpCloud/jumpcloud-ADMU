function Write-AdmuErrorMessage {
    param (
        [string]$ErrorName
    )
    switch ($ErrorName) {
        "load_unload_error" {
            Write-ToLog -Message "Load/Unload Error: The user registry cannot be loaded or unloaded. Verify that the admin running ADMU has permission to the user's NTUser.dat/UsrClass.dat. Verify that the system has permission to access and modify the registry. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors" -Level Warn

            $Script:ErrorMessage = "Load/Unload Error: User registry cannot be loaded or unloaded. Click the link below for troubleshooting information."
        }
        "copy_error" {
            Write-ToLog -Message:("Registry Copy Error: The user registry files can not be copied. Verify that the system has permission to access and modify the registry. Verify that the admin running ADMU has permission to the user's NTUser.dat/ UsrClass.dat files, no user processes/ services are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn

            $Script:ErrorMessage = "Registry Copy Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Click the link below for troubleshooting information."
        }
        "rename_registry_file_error" {
            Write-ToLog -message:("Registry Rename Error: Could not rename user registry file. Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that the system has permission to access and modify the registry. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn

            $Script:ErrorMessage = "Registry Rename Error: Registry files cannot be renamed. Click the link below for troubleshooting information."
        }
        "backup_error" {
            Write-ToLog -Message:("Registry Backup Error: Could not take a backup of the user registry files. Verify that the system has permission to access and modify the registry. Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn

            $Script:ErrorMessage = "Registry Backup Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Click the link below for troubleshooting information."
        }
        "user_init_error" {
            Write-ToLog -Message:("User Initialization Error: The new local user was created but could not be initialized.  Verify that the user was not already created before running ADMU. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn

            $Script:ErrorMessage = "User Initialization Error. Click the link below for troubleshooting information."
        }
        "user_create_error" {
            Write-ToLog -Message:("User Creation Error: The new local user could not be created. Verify that the user was not already created before running ADMU. Verify that the supplied password meets the complexity requirements on this system. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn

            $Script:ErrorMessage = "User Creation Error. Click the link below for troubleshooting information."
        }
        "user_folder_redirection_error" {
            Write-ToLog -Message:("User Folder Redirection Error: One of the user's main folder (Desktop, Downloads, Documents, Favorites, Pictures, Videos, Music) path is redirected. Verify that the user's main folders path are set to default and not redirected to another path (ie. Network Drive). Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn
            $Script:ErrorMessage = "User Folder Redirection Error. Click the link below for troubleshooting information."
        }
        "user_profile_folder_name_error" {
            Write-ToLog -Message:("User Profile Folder Name Error: The user profile folder name contains a .WORKGROUP or .ADMU suffix, which is not allowed. This indicates that the user has been migrated previously.") -Level Warn

            $Script:ErrorMessage = "User Profile Folder Name Error. Click the link below for troubleshooting information."
        }
        "user_profile_previous_sid_error" {
            Write-ToLog -Message:("User Profile Previous SID Error: The user profile has a PreviousSID key. The user has been migrated previously.") -Level Warn

            $Script:ErrorMessage = "User Profile Previously Migrated Error. Click the link below for troubleshooting information."
        }
        Default {
            Write-ToLog -Message:("Error occurred, please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Warn

            $Script:ErrorMessage = "Error occurred. Click the link below for troubleshooting information."
        }
    }
}