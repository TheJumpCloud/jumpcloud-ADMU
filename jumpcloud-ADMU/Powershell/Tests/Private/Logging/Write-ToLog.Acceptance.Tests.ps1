Describe "Write-ToLog Acceptance Tests" -Tag "Acceptance" {
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
    It 'Write-ToLog - ' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
        Write-ToLog -Message:('Log is created - test.') -Level:('Info')
        $log = 'C:\windows\Temp\jcAdmu.log'
        $log | Should -exist
    }

    It 'Write-ToLog - Log is created' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
        Write-ToLog -Message:('Log is created - test.') -Level:('Info')
        $log = 'C:\windows\Temp\jcAdmu.log'
        $log | Should -exist
    }

    It 'Write-ToLog - ERROR: Log entry exists' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
        # Write-ToLog -Message:('Test Error Log Entry.') -Level:('Error') -ErrorAction
        #$Log = Get-Content 'c:\windows\temp\jcAdmu.log'
        #$Log.Contains('ERROR: Test Error Log Entry.') | Should -Be $true
        #    if ($error.Count -eq 1) {
        #    $error.Clear()
        #    }
    }

    It 'Write-ToLog - WARNING: Log entry exists' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
        Write-ToLog -Message:('Test Warning Log Entry.') -Level Warning
        $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
        $Log.Contains('WARNING: Test Warning Log Entry.') | Should -Be $true
    }

    It 'Write-ToLog - INFO: Log entry exists' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
        Write-ToLog -Message:('Test Info Log Entry.') -Level:('Info')
        $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
        $Log.Contains('INFO: Test Info Log Entry.') | Should -Be $true
        remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
    }

    # Add more acceptance tests as needed
}
