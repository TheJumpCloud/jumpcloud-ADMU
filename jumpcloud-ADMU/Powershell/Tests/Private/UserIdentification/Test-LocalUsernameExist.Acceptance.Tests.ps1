Describe "Test-LocalUsernameExist Acceptance Tests" -Tag "Acceptance" {
    BeforeAll {
        # import all functions
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"

        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }

            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }

        . "$helpFunctionDir\$FileName"
    }

    Context "User does not exist" {

        It "returns all flags false when the local user does not exist" {
            $testUserName = "admu_test_$(Get-Random -Maximum 10000)"

            # Make sure the user really doesn't exist
            $existing = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
            if ($existing) {
                Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
            }

            $result = Test-LocalUsernameExist -JumpCloudUserName $testUserName

            $result.exists           | Should -BeFalse
            $result.jumpCloudCreated | Should -BeFalse
            $result.jumpCloudManaged | Should -BeFalse
            $result.admuCreated      | Should -BeFalse
        }
    }

    Context "Local user exists with no JumpCloud-related description" {

        It "sets only 'exists' to true" {
            $testUserName = "admu_test_$(Get-Random -Maximum 10000)"
            try {
                # Make sure the user really exist
                $existing = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-LocalUser -Name $testUserName -NoPassword -FullName "Test User" -Description "Regular local user" -ErrorAction Stop | Out-Null
                }

                $result = Test-LocalUsernameExist -JumpCloudUserName $testUserName

                $result.exists           | Should -BeTrue
                $result.jumpCloudCreated | Should -BeFalse
                $result.jumpCloudManaged | Should -BeFalse
                $result.admuCreated      | Should -BeFalse
            } finally {
                Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Local user exists and Created by JumpCloud" {

        It "sets 'exists' and 'jumpCloudCreated' to true" {
            $testUserName = "admu_test_$(Get-Random -Maximum 10000)"
            try {
                # Make sure the user really exist
                $existing = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-LocalUser -Name $testUserName -NoPassword -Description "Created by JumpCloud" -ErrorAction Stop | Out-Null
                }

                $result = Test-LocalUsernameExist -JumpCloudUserName $testUserName

                $result.exists           | Should -BeTrue
                $result.jumpCloudCreated | Should -BeTrue
                $result.jumpCloudManaged | Should -BeFalse
                $result.admuCreated      | Should -BeFalse
            } finally {
                Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Local user exists and Created by JumpCloud ADMU" {

        It "sets 'exists' and 'admuCreated' to true" {
            $testUserName = "admu_test_$(Get-Random -Maximum 10000)"
            try {
                # Make sure the user really exist
                $existing = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-LocalUser -Name $testUserName -NoPassword -Description "Created by JumpCloud ADMU" -ErrorAction Stop | Out-Null
                }

                $result = Test-LocalUsernameExist -JumpCloudUserName $testUserName

                $result.exists           | Should -BeTrue
                $result.jumpCloudCreated | Should -BeFalse
                $result.jumpCloudManaged | Should -BeFalse
                $result.admuCreated      | Should -BeTrue
            } finally {
                Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
            }
        }
    }

    Context "Local user exists and username found in manageduser.json and Created by JumpCloud ADMU" {

        It "sets 'exists', 'jumpCloudManaged' and 'admuCreated' to true" {
            $testUserName = "admu_test_$(Get-Random -Maximum 10000)"
            try {
                # Make sure the user really exist
                $existing = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-LocalUser -Name $testUserName -NoPassword -Description "Created by JumpCloud ADMU" -ErrorAction Stop | Out-Null
                }

                # Simulate entry in managedUsers.json
                $managedUsersPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\managedUsers.json'
                # Ensure the directory exists
                $managedUsersDir = Split-Path -Path $managedUsersPath -Parent
                if (-not (Test-Path -Path $managedUsersDir)) {
                    New-Item -Path $managedUsersDir -ItemType Directory -Force | Out-Null
                }
                $managedUsers = @(@{ username = $testUserName })
                $managedUsers | ConvertTo-Json | Set-Content -Path $managedUsersPath

                $result = Test-LocalUsernameExist -JumpCloudUserName $testUserName

                $result.exists           | Should -BeTrue
                $result.jumpCloudCreated | Should -BeFalse
                $result.jumpCloudManaged | Should -BeTrue
                $result.admuCreated      | Should -BeTrue
            } finally {
                Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue

                # Clean up managedUsers.json
                $managedUsersPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\managedUsers.json'
                if (Test-Path $managedUsersPath) {
                    Remove-Item -Path $managedUsersPath -ErrorAction SilentlyContinue
                }
            }
        }
    }

    Context "Local user exists and username found in manageduser.json and Created by JumpCloud" {

        It "sets 'exists', 'jumpCloudManaged' and 'jumpCloudCreated' to true" {
            $testUserName = "admu_test_$(Get-Random -Maximum 10000)"
            try {
                # Make sure the user really exist
                $existing = Get-LocalUser -Name $testUserName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-LocalUser -Name $testUserName -NoPassword -Description "Created by JumpCloud" -ErrorAction Stop | Out-Null
                }

                # Simulate entry in managedUsers.json
                $managedUsersPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\managedUsers.json'
                # Ensure the directory exists
                $managedUsersDir = Split-Path -Path $managedUsersPath -Parent
                if (-not (Test-Path -Path $managedUsersDir)) {
                    New-Item -Path $managedUsersDir -ItemType Directory -Force | Out-Null
                }
                $managedUsers = @(@{ username = $testUserName })
                $managedUsers | ConvertTo-Json | Set-Content -Path $managedUsersPath

                $result = Test-LocalUsernameExist -JumpCloudUserName $testUserName

                $result.exists           | Should -BeTrue
                $result.jumpCloudCreated | Should -BeTrue
                $result.jumpCloudManaged | Should -BeTrue
                $result.admuCreated      | Should -BeFalse
            } finally {
                Remove-LocalUser -Name $testUserName -ErrorAction SilentlyContinue

                # Clean up managedUsers.json
                $managedUsersPath = 'C:\Program Files\JumpCloud\Plugins\Contrib\managedUsers.json'
                if (Test-Path $managedUsersPath) {
                    Remove-Item -Path $managedUsersPath -ErrorAction SilentlyContinue
                }
            }
        }
    }
}