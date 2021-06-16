BeforeAll{
    Write-Host "Script Location: $PSScriptRoot"
    # translate $ModuleVersionType for [version] string matching module
    if ($env:ModuleVersionType -eq "patch")
    {
        $env:ModuleVersionType = "build"
    }
}
Describe 'Build Tests' {

    Context 'Check Files Exist' {

        It 'gui_jcadmu.exe exists' {
            (Test-Path -Path ("$PSScriptRoot\..\..\exe\gui_jcadmu.exe")) | Should -Be $true
        }

        It 'uwp_jcadmu.exe exists' {
            (Test-Path -Path ("$PSScriptRoot\..\..\exe\uwp_jcadmu.exe")) | Should -Be $true
        }
        It 'ADMU.ps1 writen to in last 2mins' -skip {
            if ((@(Get-ChildItem ("$PSScriptRoot\..\..\..\Deploy\ADMU.ps1")|Where-Object LastWriteTime -gt (Get-Date).AddMinutes(-2)).LastWriteTime).length -ge 1){$lessthan2 = $true}else{$lessthan2 = $false}
            $lessthan2| Should -Be $true
            #TODO: why this test?
        }

    }

    Context 'Check Versioning & Signature' {

        It 'XAML Form version' {
            $FormPath = "$PSScriptRoot\..\Form.ps1"
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'
            $formversion = Select-String -Path:($formpath) -Pattern:($VersionRegex)
            $branchformversion = [version]$formversion.Matches.value
            $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Form.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
            $masterformversion = [version]$masterversion.Matches.value
            $branchformversion | Should -BeGreaterThan $masterformversion
            $branchformversion.$($env:ModuleVersionType) | Should -Be ($masterformversion.$($env:ModuleVersionType) + 1)
        }

        It 'Start-Migration version' {
            $startMigrationPath = "$PSScriptRoot\..\Start-Migration.ps1"
            # $VersionRegex = [regex]"(\$admuVersion = )\'(.*?)\'"
            $VersionRegex = [regex]"(admuVersion = )'(.*?)'"
            $admuversion = Select-String -Path:($startMigrationPath) -Pattern:($VersionRegex)
            $branchStartMigrationVersion = [version]$admuversion.Matches.Groups[2].value
            $masterStartMigration = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Start-Migration.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterStartMigration) -Pattern:($VersionRegex)
            $masterStartMigrationVersion = [version]$masterVersion.Matches.Groups[2].value
            $branchStartMigrationVersion | Should -BeGreaterThan $masterStartMigrationVersion
            $branchStartMigrationVersion.$($env:ModuleVersionType) | Should -Be ($masterStartMigrationVersion.$($env:ModuleVersionType) + 1)
        }

        It 'gui_jcadmu.exe version' {
            $VersionRegex = [regex]'(?<=Title="JumpCloud ADMU )(.*?)(?=" )'
            $masterform = (Invoke-WebRequest https://raw.githubusercontent.com/TheJumpCloud/jumpcloud-ADMU/master/jumpcloud-ADMU/Powershell/Form.ps1 -useBasicParsing).tostring()
            $masterVersion = Select-String -inputobject:($masterform) -Pattern:($VersionRegex)
            $masterformversion = [version]$masterversion.Matches.value
            $exeversion = [version](Get-Item ("$PSScriptRoot\..\..\exe\gui_jcadmu.exe")).VersionInfo.FileVersion
            $exeversion | Should -BeGreaterThan $masterformversion
            $exeversion.$($env:ModuleVersionType) | Should -Be ($masterformversion.$($env:ModuleVersionType) + 1)
        }

        It 'gui_jcadmu.exe signature valid' -skip {
            #(Get-AuthenticodeSignature ($Env:BUILD_SOURCESDIRECTORY + '\jumpcloud-ADMU\exe\gui_jcadmu.exe')).Status  | Should -Be 'Valid'
            #TODO: why this test?
        }
    }
}