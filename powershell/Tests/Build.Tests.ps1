$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'Build Tests' {

    Context 'Check Files Exist' {

        It 'gui_jcadmu.exe exists' {
            (Test-Path -Path 'C:\agent\_work\1\s\exe\gui_jcadmu.exe') | Should Be $true
        }

        It 'ps2exe.ps1 exists' {
            (Test-Path -Path 'C:\tools\PS2EXE-GUI\ps2exe.ps1') | Should Be $true
        }

        It 'ADMU.ps1 created in last 2mins' {
             if(( @(Get-ChildItem 'C:\agent\_work\1\s\powershell\ADMU.ps1'|Where-Object CreationTime -gt (Get-Date).AddMinutes(-2)).CreationTime).length -ge 1){$lessthan2 = $true}else{$lessthan2 = $false} 
             $lessthan2| Should Be $true
        }
    }

    Context 'Check Versioning' {

        It 'XAML Form version' {
           $guiversion = (select-string -InputObject (get-item 'C:\agent\_work\1\s\powershell\Form.ps1') -Pattern "Title=").ToString()
           $formversion = $guiversion.Substring(69,5)
           $formversion | Should BeGreaterThan '1.2.7'
        }

        It 'gui_jcadmu.exe version' {
            $exeversion = (Get-Item 'C:\agent\_work\1\s\exe\gui_jcadmu.exe').VersionInfo.FileVersion
            $exeversion | Should BeGreaterThan '1.2.7'
        }

    }
}
