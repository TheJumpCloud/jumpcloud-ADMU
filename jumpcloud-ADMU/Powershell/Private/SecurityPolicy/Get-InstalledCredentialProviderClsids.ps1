function Get-InstalledCredentialProviderClsids {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param ()

    process {
        $providersPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
        if (-not (Test-Path $providersPath)) {
            return @()
        }

        $clsids = @(Get-ChildItem -Path $providersPath -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^\{[0-9a-fA-F-]+\}$' } |
            ForEach-Object { $_.PSChildName })

        return $clsids
    }
}
