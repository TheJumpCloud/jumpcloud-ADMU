Function Test-CharLen {
    [CmdletBinding()]
    param (
        # Char Length to test
        [Parameter(Mandatory = $true)]
        [System.Int32]
        $len,
        # String to test #allow false to allow for searching empty strings
        [Parameter(Mandatory = $false)]
        [System.String]
        $testString
    )
    If ($testString.Length -eq $len) {
        Return $true
    } Else {
        Return $false
    }
}
