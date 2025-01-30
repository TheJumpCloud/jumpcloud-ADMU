function Test-FileAttribute {
    [CmdletBinding()]
    param (
        # Profile path
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]$ProfilePath,
        # Attribute to Test
        [Parameter(Mandatory = $true)]
        [ValidateSet("ReadOnly", "Hidden", "System", "Archive", "Normal", "Temporary", "Offline")]
        [System.String]
        $Attribute
    )

    begin {
        $profileProperties = Get-ItemProperty -Path $ProfilePath
    }

    process {
        $attributes = $($profileProperties.Attributes)
    }

    end {
        if ($attributes -match $Attribute) {
            return $true
        } else {
            return $false
        }
    }
}