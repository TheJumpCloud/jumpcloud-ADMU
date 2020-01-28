$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'EXE File Checks' {

    Context 'Check Files & Folders Exist'{

       It 'gui_jcadmu.exe exists' {
         (Test-Path -Path 'C:\agent\_work\1\s\exe\gui_jcadmu.exe') | Should Be $true
        }

    }

    Context 'Check Files Versions'{

       It 'gui_jcadmu.exe version' {
       $guiversion = (select-string -InputObject (get-item 'C:\agent\_work\1\s\powershell\Form.ps1') -Pattern "Title=").ToString()
       $formversion = $guiversion.Substring(69,5)
       $formversion | Should be '1.2.7'
       }
    }
}
