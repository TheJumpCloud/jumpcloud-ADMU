function Test-RegistryValueMatch {

    param (

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$stringmatch

    )

    $ErrorActionPreference = "SilentlyContinue"
    $regvalue = Get-ItemPropertyValue -Path $Path -Name $Value
    $ErrorActionPreference = "Continue"
    $out = 'Value For ' + $Value + ' Is ' + $1 + ' On ' + $Path


    if ([string]::IsNullOrEmpty($regvalue)) {
        write-host 'KEY DOESNT EXIST OR IS EMPTY'
        return $false
    } else {
        if ($regvalue -match ($stringmatch)) {
            Write-Host $out
            return $true
        } else {
            Write-Host $out
            return $false
        }
    }
}
