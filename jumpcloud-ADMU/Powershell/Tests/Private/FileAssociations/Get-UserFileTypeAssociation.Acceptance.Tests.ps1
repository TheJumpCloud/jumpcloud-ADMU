Describe "Get-UserFileTypeAssociation Acceptance Tests" -Tag "Acceptance" {
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
        if ("HKEY_USERS" -notin (Get-psdrive | select-object name).Name) {
            Write-ToLog "Mounting HKEY_USERS to check USER UWP keys"
            New-PSDrive -Name:("HKEY_USERS") -PSProvider:("Registry") -Root:("HKEY_USERS") | Out-Null
        }
    }
    It "Should Get the User File Type Associations" {
        $currentUserSID = (Get-LocalUser -Name $env:USERNAME | Select-Object SID).SID
        # set the file type protocols
        $userFileTypeAssociations = Get-UserFileTypeAssociation -UserSid $currentUserSID -UseAdmuPath $false
        # Should not be null or empty
        $userFileTypeAssociations | Should -Not -BeNullOrEmpty
    }

    # Add more acceptance tests as needed
}
