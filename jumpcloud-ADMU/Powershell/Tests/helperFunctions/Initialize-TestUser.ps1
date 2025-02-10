# This helper function creates new local users and initializes their home directories
# If the user exists and was created by the ADMU, the tool will attempt to remove the profile
Function Initialize-TestUser {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.String]
        $UserName,
        [Parameter()]
        [System.String]
        $Password
    )
    Process {
        Write-Host "Building Profile for $($UserName)"
        if ((Get-LocalUser | Select-Object Name) -match $($UserName)) {
            Remove-LocalUserProfile $($UserName)
        }
        $newUserPassword = ConvertTo-SecureString -String "$($Password)" -AsPlainText -Force
        New-localUser -Name "$($UserName)" -password $newUserPassword -ErrorVariable userExitCode -Description "Created By JumpCloud ADMU"
        if ($userExitCode) {
            Write-Log -Message:("$userExitCode")
            Write-Log -Message:("The user: $($UserName) could not be created, exiting")
            exit 1
        }
        # Initialize the Profile
        New-LocalUserProfile -username "$($UserName)" -ErrorVariable profileInit
        if ($profileInit) {
            Write-Log -Message:("$profileInit")
            Write-Log -Message:("The user: $($UserName) could not be initialized, exiting")
            exit 1
        }
    }
}
