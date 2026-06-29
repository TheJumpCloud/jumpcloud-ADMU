function Set-ExcludedCredentialProviders {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [System.String[]]
        $Clsids,

        [Parameter(Mandatory = $false)]
        [System.String]
        $RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    )

    process {
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }

        $normalizedClsids = @($Clsids | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
        if ($normalizedClsids.Count -eq 0) {
            Remove-ItemProperty -Path $RegPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue
            return
        }

        $value = ($normalizedClsids -join ',')
        Set-ItemProperty -Path $RegPath -Name 'ExcludedCredentialProviders' -Value $value -Type String
    }
}
