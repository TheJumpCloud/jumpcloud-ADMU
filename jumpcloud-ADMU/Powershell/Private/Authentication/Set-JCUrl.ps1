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
            }
            "EU" {
                $global:JCUrl = "https://console.eu.jumpcloud.com"
            }
        }
    }
}