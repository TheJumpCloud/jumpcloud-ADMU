$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'Build Tests' {

    Context 'Check Files Exist' {

        It 'gui_jcadmu.exe exists' {
            (Test-Path -Path 'C:\agent\_work\1\s\exe\gui_jcadmu.exe') | Should Be $true
        }

        It 'ADMU.ps1 writen to in last 2mins' {
            if((@(Get-ChildItem 'C:\agent\_work\1\s\powershell\ADMU.ps1'|Where-Object LastWriteTime -gt (Get-Date).AddMinutes(-2)).LastWriteTime).length -ge 1){$lessthan2 = $true}else{$lessthan2 = $false}
            $lessthan2| Should Be $true
        }
    }

    Context 'Check Versioning' {

        It 'XAML Form version' {
           $masterform = Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/powershell/Form.ps1
           $masterformver = $masterform.Content.Substring(584,5)
           $guiversion = (select-string -InputObject (get-item 'C:\agent\_work\1\s\powershell\Form.ps1') -Pattern "Title=").ToString()
           $formversion = $guiversion.Substring(69,5)
           $formversion | Should BeGreaterThan $masterformver
        }

        It 'gui_jcadmu.exe version' {
            $masterform = Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/powershell/Form.ps1
            $masterformver = $masterform.Content.Substring(584,5)
            $exeversion = (Get-Item 'C:\agent\_work\1\s\exe\gui_jcadmu.exe').VersionInfo.FileVersion
            $exeversion | Should BeGreaterThan $masterformver
        }

    }
}