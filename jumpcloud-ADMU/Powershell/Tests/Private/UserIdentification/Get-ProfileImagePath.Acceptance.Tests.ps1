Describe "Get-ProfileImagePath Acceptance Tests" -Tag "Acceptance" {
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
    It "Should return a valid profile image path given a user's SID" {
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        $profileImagePath = Get-ProfileImagePath -UserSid $currentUserSID
        $profileImagePath | should -Exist
    }
    It "Should throw if an invalid user SID is passed into the function" {
        $invalidUserSID = "invalidSID"
        { Get-ProfileImagePath -UserSid $invalidUserSID } | should -Throw
    }
}
