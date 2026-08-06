function ConvertTo-UsersRegistrySubKey {
    <#
    .SYNOPSIS
        Normalizes an HKEY_USERS / HKU path to a subkey path for Microsoft.Win32.Registry::Users.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $subKey = $Path.Trim()
    $subKey = $subKey -replace '^(?i)HKEY_USERS:\\', ''
    $subKey = $subKey -replace '^(?i)HKU:\\', ''
    $subKey = $subKey -replace '^(?i)HKEY_USERS\\', ''
    $subKey = $subKey -replace '^(?i)HKU\\', ''
    return $subKey.TrimStart('\')
}
