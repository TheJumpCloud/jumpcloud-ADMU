Describe "Stop-FileLockingProcess Acceptance Tests" -Tag "Acceptance" {
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

        if ($helpFunctionDir) {
            . "$helpFunctionDir\$fileName"
        }

        # Setup test variables: Create a unique temporary file path for the tests
        $Script:testFilePath = Join-Path -Path $env:TEMP -ChildPath "ADMU_LockTest_$([guid]::NewGuid()).txt"
    }

    BeforeEach {
        # Ensure a clean test file exists before each block
        New-Item -Path $Script:testFilePath -ItemType File -Force | Out-Null
    }

    AfterEach {
        # Clean up the test file
        if (Test-Path $Script:testFilePath) {
            Remove-Item -Path $Script:testFilePath -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        # Failsafe cleanup: Kill any lingering test background processes if a test failed mid-execution
        Get-Process -Name "powershell" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "ADMU_LockTest" } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    }

    It "Should return silently and not throw an error if the target file does not exist" {
        # Arrange: Ensure file is missing
        Remove-Item -Path $Script:testFilePath -Force -ErrorAction SilentlyContinue

        # Act & Assert
        { Stop-FileLockingProcess -FilePath $Script:testFilePath } | Should -Not -Throw
    }

    It "Should execute without error when the file exists but is not locked by any process" {
        # Arrange: File exists (created in BeforeEach) but nothing is holding it

        # Act & Assert
        { Stop-FileLockingProcess -FilePath $Script:testFilePath } | Should -Not -Throw
    }

    It "Should detect and terminate a background process holding an exclusive lock on the file" {
        # Arrange: Spawn a background PowerShell process that locks the file
        $lockCode = "try { `$stream = [System.IO.File]::Open('$($Script:testFilePath)', [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None); while (`$true) { Start-Sleep -Seconds 1 } } catch { }"
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($lockCode))

        # Launch the rogue process silently
        $bgProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-WindowStyle Hidden -NoProfile -EncodedCommand $encodedCommand" -PassThru

        # Wait for the background process to spin up and grab the lock
        Start-Sleep -Seconds 3

        # Validate setup: Ensure the file is actually locked (trying to open it should throw an error)
        { [System.IO.File]::Open($Script:testFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) } | Should -Throw

        # Act: Call the ADMU defense function
        Stop-FileLockingProcess -FilePath $Script:testFilePath

        # Assert: The background process should be dead
        $bgProcess.HasExited | Should -Be $true

        # Assert: The file lock should now be released (we can open and close it safely)
        {
            $testStream = [System.IO.File]::Open($Script:testFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $testStream.Dispose()
        } | Should -Not -Throw
    }

    It "Should ignore the current script's PID and not terminate itself" {
        # Arrange: Lock the file from *within* the current Pester test process
        $fileStream = [System.IO.File]::Open($Script:testFilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)

        # Act: Call the function. It will detect the lock, but should bypass termination because the PID matches $PID
        { Stop-FileLockingProcess -FilePath $Script:testFilePath } | Should -Not -Throw

        # Assert: If we reached this line, the process didn't kill itself.
        $true | Should -Be $true

        # Teardown: Release our own lock so AfterEach can delete the test file
        $fileStream.Dispose()
    }
}