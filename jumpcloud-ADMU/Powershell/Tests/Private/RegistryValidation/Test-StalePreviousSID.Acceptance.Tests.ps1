Describe "Test-StalePreviousSID Acceptance Tests" -Tag "Acceptance" {
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

        $ownSid = 'S-1-5-21-1111111111-2222222222-3333333333-1001'
        $otherSid = 'S-1-5-21-1111111111-2222222222-3333333333-1002'
    }
    It "Returns true when the value is the account's own SID and ProfileList still maps the original folder" {
        Test-StalePreviousSID -PreviousSid $ownSid -UserSid $ownSid -ProfileImagePath 'C:\Users\testuser' | Should -BeTrue
    }
    It "Returns false when the value is a different SID, as written by a completed migration" {
        Test-StalePreviousSID -PreviousSid $otherSid -UserSid $ownSid -ProfileImagePath 'C:\Users\testuser' | Should -BeFalse
    }
    It "Returns false when ProfileList maps the SID to a folder with the .ADMU suffix" {
        Test-StalePreviousSID -PreviousSid $ownSid -UserSid $ownSid -ProfileImagePath 'C:\Users\testuser.ADMU' | Should -BeFalse
    }
    It "Returns false when the ProfileList path is not available" {
        Test-StalePreviousSID -PreviousSid $ownSid -UserSid $ownSid | Should -BeFalse
        Test-StalePreviousSID -PreviousSid $ownSid -UserSid $ownSid -ProfileImagePath '' | Should -BeFalse
    }
}
