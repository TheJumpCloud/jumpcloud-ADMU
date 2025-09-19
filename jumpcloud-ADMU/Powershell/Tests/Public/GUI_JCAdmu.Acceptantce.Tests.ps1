Describe "GUI Parameters Acceptance Tests" -Tag "Migration Parameters" {

    # Import common functions and find the executable before running tests.
    BeforeAll {
        # Dynamically find and import helper functions.
        $currentPath = $PSScriptRoot # Start from the current script's directory.
        $TargetDirectory = "helperFunctions"
        $FileName = "Import-AllFunctions.ps1"
        while ($currentPath -ne $null) {
            $filePath = Join-Path -Path $currentPath -ChildPath $TargetDirectory
            if (Test-Path $filePath) {
                $helpFunctionDir = $filePath
                break
            }
            # Move one directory up.
            $currentPath = Split-Path $currentPath -Parent
        }
        . "$helpFunctionDir\$fileName"

        # Import the user initialization function.
        . "$helpFunctionDir\Initialize-TestUser.ps1"

        # Define the path to the GUI executable.
        $guiPath = Join-Path $PSScriptRoot '..\..\..\..\jumpCloud-Admu\Exe\gui_jcadmu.exe'
        if (-Not (Test-Path -Path $guiPath)) {
            throw "GUI executable not found at path: $($guiPath)"
        }
    }

    Context "Standard Migration via EXE" {

        # Test Setup
        BeforeEach {
            # sample password
            $tempPassword = "Temp123!Temp123!"
            # username to migrate
            $userToMigrateFrom = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })
            # username to migrate to
            $userToMigrateTo = "ADMU_" + -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

            # Initialize-TestUser
            Initialize-TestUser -username $userToMigrateFrom -password $tempPassword
            # define test case input
            $testCaseInput = @{
                JumpCloudUserName       = $userToMigrateTo
                SelectedUserName        = $userToMigrateFrom
                TempPassword            = $tempPassword
                LeaveDomain             = $false
                ForceReboot             = $false
                UpdateHomePath          = $false
                InstallJCAgent          = $false
                AutoBindJCUser          = $false
                BindAsAdmin             = $false
                SetDefaultWindowsUser   = $true
                AdminDebug              = $false
                JumpCloudConnectKey     = $null
                JumpCloudAPIKey         = $null
                JumpCloudOrgID          = $null
                ValidateUserShellFolder = $true
                SystemContextBinding    = $false
                JumpCloudUserID         = $null
            }
            # remove the log
            $logPath = "C:\Windows\Temp\jcadmu.log"
            if (Test-Path -Path $logPath) {
                Remove-Item $logPath
                New-Item $logPath -Force -ItemType File
            }
            $argumentList = [System.Collections.Generic.List[string]]::new()
            # Iterate through each key-value pair in the original hashtable.
            # Iterate through each key-value pair in the original hashtable.
            foreach ($entry in $testCaseInput.GetEnumerator()) {
                $key = $entry.Key
                $value = $entry.Value

                # Skip null values as they don't typically need to be passed as arguments.
                if ($null -eq $value) {
                    continue
                }

                # Format the value. Booleans are converted to lowercase string literals like '$true'.
                # Other types are used as-is (they will be converted to strings automatically).
                $formattedValue = if ($value -is [bool]) {
                    '$' + $value.ToString().ToLower()
                } else {
                    $value
                }

                # Construct the argument string in the format -Key:Value
                $argument = "-{0}:{1}" -f $key, $formattedValue
                $argumentList.Add($argument)
                Write-Host "Constructed argument: $argument"
            }
        }

        It "Should migrate a user successfully using required command-line parameters" {
            # Arrange
            Write-Host "$($testCaseInput | Out-String)"
            { . $guiPath $argumentList.ToArray() } | Should -Not -Throw
            $logs = Get-Content -Path "C:\Windows\Temp\jcAdmu.log" -Raw
            $logs | Should -Not -BeNullOrEmpty
            Write-Host $logs
            $logs | Should -Match "Script finished successfully"


        }
    }
}