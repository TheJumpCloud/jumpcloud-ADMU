$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'EXE Folder Checks' {

    Context 'Check Files & Folders Exist'{

       It 'gui_jcadmu_win7.exe exists' {
        Test-Path -Path 'C:\agent\_work\2\s\exe\Windows 7\gui_jcadmu_win7.exe' | Should Be $true
       }

       It 'jcadmu_win7.exe exists' {
        Test-Path -Path 'C:\agent\_work\2\s\exe\Windows 7\jcadmu_win7.exe' | Should Be $true
       }

       It 'gui_jcadmu_win10.exe exists' {
         Test-Path -Path 'C:\agent\_work\2\s\exe\Windows 8-10\gui_jcadmu_win10.exe' | Should Be $true
        }

        It 'jcadmu_win10.exe exists' {
         Test-Path -Path 'C:\agent\_work\2\s\exe\Windows 8-10\jcadmu_win10.exe' | Should Be $true
        }
    }

    Context 'Check Files Versions'{

        It 'gui_jcadmu_win7.exe version' {
            #check exe version number
         Test-Path -Path 'C:\agent\_work\2\s\exe\Windows 7\gui_jcadmu_win7.exe' | Should Be $true
        }
     }
}
