function Test-RegistryValueMatch {

    param (

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$stringMatch

    )

    $ErrorActionPreference = "SilentlyContinue"
    $regValue = Get-ItemPropertyValue -Path $Path -Name $Value
    $ErrorActionPreference = "Continue"
    $out = 'Value For ' + $Value + ' Is ' + $1 + ' On ' + $Path


    if ([string]::IsNullOrEmpty($regValue)) {
        write-host 'KEY DOES NOT EXIST OR IS EMPTY'
        return $false
    } else {
        if ($regValue -match ($stringMatch)) {
            Write-Host $out
            return $true
        } else {
            Write-Host $out
            return $false
        }
    }
}
