$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'Build Tests' {

    Context 'Check Files Exist'{

       It 'ps2exe.ps1 exists' {
         (Test-Path -Path '"C:\tools\PS2EXE-GUI\ps2exe.ps1"') | Should Be $true
        }


    }

}
