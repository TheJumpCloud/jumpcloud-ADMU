Describe 'Migration' {

    Context 'Domain Join Status'{

       It 'partOfDomain is $true' {

        Mock -CommandName Get-WmiObject
        $WmiComputerSystem = [PSCustomObject]@{}
        Add-Member -InputObject:($WmiComputerSystem) -MemberType:('NoteProperty') -Name:('partOfDomain') -Value:($false)

        $WmiComputerSystem.partOfDomain | Should Be $true
       }
    }
}