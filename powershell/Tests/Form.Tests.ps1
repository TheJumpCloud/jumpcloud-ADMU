Describe 'Form' {

    Context 'Read XAML'{

       It 'Valid XAML' {
        #SETUP
        #DOSOMETHING | Should Be $true
       }

       It 'Invalid XAML' {
        #SETUP
        #DOSOMETHING | Should Be $false

    }
    }

    Context 'Domain Check'{

        It 'Is part of a domain' {
         #SETUP
         Mock -CommandName Get-WmiObject

         $gwmiobject = [PSCustomObject]@{}
         Add-Member -InputObject:($gwmiobject) -MemberType:('NoteProperty') -Name:('PartOfDomain') -Value:($true)

         $gwmiobject.PartOfDomain | Should Be $true
        }
     }

}