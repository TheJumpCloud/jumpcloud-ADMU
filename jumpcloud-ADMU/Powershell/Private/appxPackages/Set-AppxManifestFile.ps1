Function Set-AppxManifestFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [system.string]
        $profileImagePath,
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [System.Object]
        $appxList
    )
    begin {
        $path = "$profileImagePath\AppData\Local\JumpCloudADMU"
        $file = "$path\appx_manifest.csv"
    }
    process {
        # Test if the directory exists. If not, create it recursively.
        if (!(Test-Path -Path $path -PathType Container)) {
            New-Item -ItemType Directory -Force -Path $path | Out-Null
        }

        if ($appxList) {
            $nonNullAppxList = ($appxList | Where-Object { $null -ne $_.InstallLocation })
            $nonNullAppxList | Export-Csv -Path $file -Force
        }

        # Get file data
        $fileDetails = Get-Item -Path $file
        $fileSize = if ($fileDetails.Length -gt 0) {
            [math]::ceiling($fileDetails.Length / 1024)
        } else {
            0
        }
    }
    end {
        Write-ToLog "appXManifest written: $($fileDetails.LastWriteTime), size: $($fileSize)kb" -Level Verbose -Step "Set-AppxManifestFile"
    }
}
