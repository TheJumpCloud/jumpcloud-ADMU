$Script:ErrorMessage = $null
function Error-Map {
    param (
        [string]$ErrorName
    )
    switch ($ErrorName) {
        "load_unload_error" {
            Write-ToLog -Message "Load/Unload Error: User registry cannot be loaded or unloaded. Verify that the admin running ADMU has permission to the user's NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors" -Level Error

            $Script:ErrorMessage = "Load/Unload Error: User registry cannot be loaded or unloaded. Please go to log file for more information."
        }
        "copy_error" {
            Write-ToLog -Message:("Copy Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Copy Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Please go to log file for more information."
        }
        "rename_original_registry_file_error" {
            Write-ToLog -message:("Rename Error: Registry files cannot be renamed. Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Rename Error: Registry files cannot be renamed. Please go to log file for more information."
        }

        "rename_backup_registry_file_error" {
            Write-ToLog -Message:("Rename Error: NTUser.dat could not be renamed to NTUser.dat.bak. Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Rename Error: NTUser.dat could not be renamed to NTUser.dat.bak. Please go to log file for more information."
        }
        "backup_error" {
            Write-ToLog -Message:("Registry Backup Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Registry Backup Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Please go to log file for more information."
        }
        "user_unit_error" {
            Write-ToLog -Message:("User Initialize Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running or the user is already created. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "User Initialize Error. Please go to log file for more information."
        }
        "user_create_error" {
            Write-ToLog -Message:("User Create Error: Verify that the admin running ADMU has permission to NTUser.dat/UsrClass.dat. Verify that no user processes/ services for the migration user are running or the user is already created. Please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "User Create Error. Please go to log file for more information."
        }
        Default {
            Write-ToLog -Message:("Error occurred, please refer to this link for more information: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors") -Level Error

            $Script:ErrorMessage = "Error occurred, please refer to log file for more information."
        }
    }
}