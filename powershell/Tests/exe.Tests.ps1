$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'EXE File Checks' {

    Context 'Check Files & Folders Exist'{

       It 'gui_jcadmu.exe exists' {
         (Test-Path -Path 'C:\agent\_work\1\s\exe\gui_jcadmu.exe') | Should Be $true
        }

        It 'jcadmu_win10.exe exists' {
         (Test-Path -Path 'C:\agent\_work\1\s\exe\jcadmu.exe') | Should Be $true
        }
    }

    Context 'Check Files Versions'{

     }
}
