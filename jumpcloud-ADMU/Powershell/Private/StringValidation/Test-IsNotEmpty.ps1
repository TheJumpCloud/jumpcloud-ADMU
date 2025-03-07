Function Test-IsNotEmpty ([System.String] $field) {
    If (([System.String]::IsNullOrEmpty($field))) {
        Return $true
    } Else {
        Return $false
    }
}