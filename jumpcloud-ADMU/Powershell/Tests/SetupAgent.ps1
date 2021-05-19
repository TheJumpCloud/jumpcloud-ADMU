# This file should build the env needed to test on a windows agent.

# Dot-source the variables for setupAgent/ migration tests:
. $PSScriptRoot\BuildVariables.ps1
# Dot-source start-migration
. ..\Start-Migration.ps1

# For each user in testing hash, create new user with the specified password and init the account
forEach ($User in $userTestingHash.Values)
{
    "Testing Case for $($User.Username)"
    $newUserPassword = ConvertTo-SecureString -String "$($User.Password)" -AsPlainText -Force
    New-localUser -Name "$($User.Username)" -password $newUserPassword -ErrorVariable userExitCode -Description "Created By JumpCloud ADMU"
    if ($userExitCode)
    {
        Write-Log -Message:("$userExitCode")
        Write-Log -Message:("The user: $($User.Username) could not be created, exiting")
        exit #TODO: error instead
    }
    # Initialize the Profile
    New-LocalUserProfile -username "$($User.Username)" -ErrorVariable profileInit
    if ($profileInit)
    {
        Write-Log -Message:("$profileInit")
        Write-Log -Message:("The user: $($User.Username) could not be initalized, exiting")
        exit #TODO: error instead
    }
}

# End region for test user generation
