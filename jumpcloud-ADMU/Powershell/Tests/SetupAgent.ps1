# This file should build the env needed to test on a windows agent.

# Dot-source the variables for setupAgent/ migration tests:
. $PSScriptRoot\BuildVariables.ps1
# Dot-source private functions
$Private = @( Get-ChildItem -Path "$PSScriptRoot/../Private/*.ps1" -Recurse)
Foreach ($Import in $Private) {
    Try {
        . $Import.FullName
    } Catch {
        Write-Error -Message "Failed to import function $($Import.FullName): $_"
    }
}

# This helper function creates new local users and initializes their home directories
# If the user exists and was created by the ADMU, the tool will attempt to remove the profile
Function InitUser {
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
            Write-Log -Message:("The user: $($UserName) could not be initalized, exiting")
            exit 1
        }
    }
}

