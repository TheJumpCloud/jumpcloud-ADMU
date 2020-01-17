Describe 'GPO Folder Checks' {

    Context 'Check Files & Folders Exist'{

       It 'manifest.xml exists' {
           Test-Path -Path 'C:\agent\_work\1\s\gpo\manifest.xml' | Should Be $true
       }

    }
}