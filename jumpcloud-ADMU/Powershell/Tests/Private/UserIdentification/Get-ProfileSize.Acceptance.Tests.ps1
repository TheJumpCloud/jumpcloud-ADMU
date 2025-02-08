Describe "Get-ProfileSize Acceptance Tests" {
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
    It "Should return the profile size of a given profile" {
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        $profileImagePath = Get-ProfileImagePath -UserSid $currentUserSID
        # get the profile size of the current user
        $profileSize = Get-ProfileSize -ProfilePath $profileImagePath
        # the profile size should be returned
        $profileSize | Should -Not -BeNullOrEmpty
    }

}
