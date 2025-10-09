function Set-FileAttribute {
    [CmdletBinding()]
    param (
        # Profile path
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path $_ })]
        [System.String]
        $ProfilePath,
        # Attribute to Remove
        [Parameter(Mandatory = $true)]
        [ValidateSet("ReadOnly", "Hidden", "System", "Archive", "Normal", "Temporary", "Offline")]
        [System.String]
        $Attribute,
        # Operation verb (add/ remove)
        [Parameter(Mandatory = $true)]
        [ValidateSet( "Add", "Remove" )]
        [System.String]
        $Operation
    )

    begin {
        $profilePropertiesBefore = Get-ItemProperty -Path $ProfilePath
        $attributesBefore = $($profilePropertiesBefore.Attributes)
    }

    process {
        Write-ToLog "$profilePath attributes before: $($attributesBefore)" -Level Verbose -Step "Set-FileAttribute"
        # remove item with bitwise operators, keeping what was set but removing the $attribute
        switch ($Operation) {
            "Remove" {
                $profilePropertiesBefore.Attributes = $profilePropertiesBefore.Attributes -band -bnot [System.IO.FileAttributes]::$Attribute
            }
            "Add" {
                $profilePropertiesBefore.Attributes = $profilePropertiesBefore.Attributes -bxor [System.IO.FileAttributes]::$Attribute
            }
        }
        $attributeTest = Test-FileAttribute -ProfilePath $ProfilePath -Attribute $Attribute
    }
    end {
        $profilePropertiesAfter = Get-ItemProperty -Path $ProfilePath
        $attributesAfter = $($profilePropertiesBefore.Attributes)
        Write-ToLog "$profilePath attributes after: $($attributesAfter)" -Level Verbose -Step "Set-FileAttribute"

        if ($attributeTest) {
            return $true
        } else {
            return $false
        }
    }
}
