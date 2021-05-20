Describe 'GPO Folder Checks' {

    Context 'Check Files & Folders Exist'{

       It 'manifest.xml exists' -skip {
           (Test-Path -Path ($Env:BUILD_SOURCESDIRECTORY + '\jumpcloud-ADMU\Gpo\manifest.xml')) | Should -Be $true
       }

    }
}