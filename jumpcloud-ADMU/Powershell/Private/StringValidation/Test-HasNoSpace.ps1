Function Test-HasNoSpace ([System.String] $field) {
    If ($field -like "* *") {
        Return $false
    } Else {
        Return $true
    }
}