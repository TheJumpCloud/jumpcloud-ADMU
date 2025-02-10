Describe "Remove-ItemIfExist Acceptance Tests" {
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
    It 'Remove-ItemIfExist - Does Exist c:\windows\temp\test\' {
        if (Test-Path 'c:\windows\Temp\test\') {
            Remove-Item 'c:\windows\Temp\test' -Recurse -Force
        }
        New-Item -ItemType directory -path 'c:\windows\Temp\test\'
        New-Item 'c:\windows\Temp\test\test.txt'
        Remove-ItemIfExist -Path 'c:\windows\Temp\test\' -Recurse
        Test-Path 'c:\windows\Temp\test\' | Should -Be $false
    }

    It 'Remove-ItemIfExist - Fails c:\windows\temp\test\' {
        if ((Test-Path 'C:\Windows\Temp\jcAdmu.log') -eq $true) {
            remove-item -Path 'C:\windows\Temp\jcAdmu.log' -Force
        }
        Mock Remove-ItemIfExist { Write-ToLog -Message ('Removal Of Temp Files & Folders Failed') -Level Warn }
        Remove-ItemIfExist -Path 'c:\windows\Temp\test\'
        $Log = Get-Content 'c:\windows\temp\jcAdmu.log'
        $Log.Contains('Removal Of Temp Files & Folders Failed') | Should -Be $true
    }
    # Add more acceptance tests as needed
}
