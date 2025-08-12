Describe "Test-PreviousSID Acceptance Tests" -Tag "Acceptance" {
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
    It 'Validates the function Test-PreviousSID returns $false if PreviousSID is not present' {
        # Get the current user SID
        $currentUserSid = (Get-LocalUser -Name $env:USERNAME).SID.Value
        # Create a test registry key for the current user
        if (-not (Get-PSDrive -Name 'HKEY_USERS' -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name 'HKEY_USERS' -PSProvider 'Registry' -Root 'HKEY_USERS' | Out-Null
        }
        New-Item -Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" -Force | Out-Null
        # Ensure the key is created
        Test-Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" | Should -Be $true
        # Run the test function
        Test-PreviousSID -UserSid $currentUserSid | Should -Be $false
        # Clean up
        Remove-Item -Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" -Recurse -Force | Out-Null
    }

    It "Validates the function Test-PreviousSID returns $true if PreviousSID is present" {
        # Get the current user SID
        $currentUserSid = (Get-LocalUser -Name $env:USERNAME).SID.Value
        # Create a test registry key for the current user
        if (-not (Get-PSDrive -Name 'HKEY_USERS' -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name 'HKEY_USERS' -PSProvider 'Registry' -Root 'HKEY_USERS' | Out-Null
        }
        New-Item -Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" -Force | Out-Null
        # Ensure the key is created
        Test-Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" | Should -Be $true
        # Set the PreviousSID value
        Set-ItemProperty -Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" -Name "PreviousSID" -Value "S-1-5-21-1234567890-1234567890-1234567890-1001" -Force
        # Run the test function
        Test-PreviousSID -UserSid $currentUserSid | Should -Be $true
        # Clean up
        Remove-Item -Path "HKEY_USERS:\$($currentUserSid)\Software\JCADMU" -Recurse -Force | Out-Null
    }

    # Add more acceptance tests as needed
}
