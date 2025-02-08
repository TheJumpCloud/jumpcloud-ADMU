Describe "Test-LocalUserName Acceptance Tests" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                # File found! Return the full path.
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"
    }
    It 'Validates user without a SID is identified' {
        # This test requires a windows device to create the get the user
        $userName = "TesterUser12345"
        $password = "TesterPassword12345!!"
        $newUserPassword = ConvertTo-SecureString -String "$($Password)" -AsPlainText -Force
        New-localUser -Name "$($UserName)" -password $newUserPassword -Description "Created By JumpCloud ADMU"

        # Get Win32 Profiles to merge data with valid SIDs
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        # get localUsers (can contain users who have not logged in yet/ do not have a SID)
        $nonSIDLocalUsers = Get-LocalUser
        Test-LocalUsername -username $userName -win32UserProfiles $win32UserProfiles -localUserProfiles $nonSIDLocalUsers | Should -Be $true
    }

    It 'Should not return true when a username does not exist' {

        # Get Win32 Profiles to merge data with valid SIDs
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        # get localUsers (can contain users who have not logged in yet/ do not have a SID)
        $nonSIDLocalUsers = Get-LocalUser
        Test-LocalUsername -username 'blazarz' -win32UserProfiles $win32UserProfiles -localUserProfiles $nonSIDLocalUsers | Should -Be $false
    }

    # Add more acceptance tests as needed
}
