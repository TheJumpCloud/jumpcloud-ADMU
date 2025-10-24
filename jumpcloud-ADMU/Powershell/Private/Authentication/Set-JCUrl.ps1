# Function to initialize the JumpCloud URI based on region
function Set-JCUrl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Region = "US"
    )
    process {
        switch ($Region) {
            "US" {
                $global:JCUrl = "https://console.jumpcloud.com"
                Write-ToLog -Message "JumpCloud URI set to US endpoint." -Level Info
            }
            "EU" {
                $global:JCUrl = "https://console.eu.jumpcloud.com"
                Write-ToLog -Message "JumpCloud URI set to EU endpoint." -Level Info
            }
        }
    }
}