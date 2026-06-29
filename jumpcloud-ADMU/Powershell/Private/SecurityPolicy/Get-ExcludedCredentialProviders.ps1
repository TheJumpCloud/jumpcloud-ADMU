function Get-ExcludedCredentialProviders {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]
        $RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    )

    process {
        $rawValue = (Get-ItemProperty -Path $RegPath -Name 'ExcludedCredentialProviders' -ErrorAction SilentlyContinue).ExcludedCredentialProviders
        if ([string]::IsNullOrWhiteSpace($rawValue)) {
            return @()
        }

        return @($rawValue -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
}
