$psfolder = Split-Path -Path:($MyInvocation)
Write-Output $psfolder
Describe 'Build Tests' {

    Context 'Check Files Exist' {

        It 'gui_jcadmu.exe exists' {
            (Test-Path -Path ('..\exe\gui_jcadmu.exe')) | Should -Be $true
        }

        It 'uwp_jcadmu.exe exists' {
            (Test-Path -Path ('..\exe\uwp_jcadmu.exe')) | Should -Be $true
        }
        It 'ADMU.ps1 writen to in last 2mins' {
            if((@(Get-ChildItem ('..\..\Deploy\ADMU.ps1')|Where-Object LastWriteTime -gt (Get-Date).AddMinutes(-2)).LastWriteTime).length -ge 1){$lessthan2 = $true}else{$lessthan2 = $false}
            $lessthan2| Should -Be $true
            #TODO: why this test?
        }

    }

    Context 'Check Versioning & Signature' {

        It 'XAML Form version' {
           $FormPath = '.\Form.ps1'
           $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'
           $formversion = Select-String -Path:($formpath) -Pattern:($VersionRegex)
           $branchformversion = [version]$formversion.Matches.value
           $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Form.ps1 -useBasicParsing).tostring()
           $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
           $masterformversion = [version]$masterversion.Matches.value
           $branchformversion | Should -BeGreaterThan $masterformversion
        }

        It 'Start-Migration version' {
            $startMigrationPath = '.\Start-Migration.ps1'
            # $VersionRegex = [regex]"(\$admuVersion = )\'(.*?)\'"
            $VersionRegex = [regex]"(admuVersion = )'(.*?)'"
            $admuversion = Select-String -Path:($startMigrationPath) -Pattern:($VersionRegex)
            $branchStartMigrationVersion = [version]$admuversion.Matches.Groups[2].value
            $masterStartMigration = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Start-Migration.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterStartMigration) -Pattern:($VersionRegex)
            $masterStartMigrationVersion = [version]$masterVersion.Matches.Groups[2].value
            $branchStartMigrationVersion | Should -BeGreaterThan $masterStartMigrationVersion
        }

        It 'gui_jcadmu.exe version' {
           $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'
           $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Form.ps1 -useBasicParsing).tostring()
           $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
           $masterformversion = [version]$masterversion.Matches.value
           $exeversion = [version](Get-Item ('..\exe\gui_jcadmu.exe')).VersionInfo.FileVersion
           $exeversion | Should -BeGreaterThan $masterformversion
        }

        It 'gui_jcadmu.exe signature valid' -skip {
            #(Get-AuthenticodeSignature ($Env:BUILD_SOURCESDIRECTORY + '\jumpcloud-ADMU\exe\gui_jcadmu.exe')).Status  | Should -Be 'Valid'
            #TODO: why this test?
         }
    }
}