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
           $RootPath = $PSScriptRoot
           $FormPath = $RootPath + '\Form.ps1'
           $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'

           $formversion = Select-String -Path:($formpath) -Pattern:($VersionRegex)
           $branchformversion = [version]$formversion.Matches.value

           $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/powershell/Form.ps1).tostring()
           $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
           $masterformversion = [version]$masterversion.Matches.value

           $branchformversion | Should BeGreaterThan $masterformversion
        }

        It 'gui_jcadmu.exe version' {

           $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'

           $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/powershell/Form.ps1).tostring()
           $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
           $masterformversion = [version]$masterversion.Matches.value

           $exeversion = (Get-Item 'C:\agent\_work\1\s\exe\gui_jcadmu.exe').VersionInfo.FileVersion

           $exeversion | Should BeGreaterThan $masterformversion
        }

    }
}