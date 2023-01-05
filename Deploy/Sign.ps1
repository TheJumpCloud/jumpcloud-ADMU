# Sign Variables
$signpath = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.17763.0/x86/signtool.exe'
$RootPath = Split-Path (Split-Path $PSScriptRoot -Parent)
# file paths
$GUI_JCADMU = "$RootPath/jumpcloud-ADMU/jumpcloud-ADMU/Exe/gui_jcadmu.exe"
$UWP_JCADMU = "$RootPath/jumpcloud-ADMU/jumpcloud-ADMU/Exe/uwp_jcadmu.exe"
$JCADMU_CAT = "$RootPath/jumpcloud-ADMU/ADMU.cat"
# cert variables
$base64 = "$env:BASE64_ENCODED_CERT"
$password = "$env:CERTPASS"
$filenameCert = "$PSScriptRoot/cert.pfx"
$bytes = [convert]::FromBase64String($base64)
# write out cert
[IO.File]::WriteAllBytes($filenameCert, $bytes)

# define function to sign required files
function Set-FileCertificate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.String]
        $passwd,
        [Parameter()]
        [System.String]
        $alg,
        [Parameter()]
        [System.String]
        $filePath,
        [Parameter()]
        [System.String]
        $certFilePath

    )
    begin {
        New-Variable -Name MaxAttempts -Option Constant -Value 5
        # Add backup TSA Servers (RFC 3161) in case we get rate-limited
        $tsaServers = @(
            "http://tsa.starfieldtech.com",
            "https://timestamp.geotrust.com/tsa",
            "http://timestamp.apple.com/ts01"
        )
        # test file path
        If (Test-Path -Path ($filePath)) {
            Write-Output "[status] Attempting to sign $filePath"
        } else {
            Write-Output "[status] $filePath not found"
            exit 1
        }
        # test cert path
        if (test-path($certFilePath)) {
            Write-Output "[status] Cert found"
        } else {
            Write-Output "[status] Cert not found, exiting"
            exit 1
        }

    }
    process {
        $tsaIndex = 0
        $attempts = 1
        while ($True) {
            Write-Output "[status] attempting to sign with $($tsaServers[$tsaIndex])"
            & $signpath sign `
                /f $certFilePath `
                /fd $alg `
                /p $passwd `
                /tr http://timestamp.digicert.com `
                $filePath
            if ( -not $? ) {
                if ($attempts -le $MaxAttempts) {
                    Write-Output "[status] attempt $attempts failed, retrying..."
                    $attempts++
                    Start-Sleep -Seconds 15
                    Continue
                } Else {
                    if ($tsaIndex -lt $tsaServers.Count) {
                        Write-Output "[status] trying a different TSA Server $($tsaServers[$tsaIndex])"
                        $tsaIndex++
                        $attempts = 1
                        Continue
                    } Else {
                        Write-Output "[status] Failed to sign $filePath, error=$error"
                        Exit 1
                    }
                }
            } Else {
                Break
            }
        }
    }
    end {
        Write-Output "[status] Digitally Signed $filePath"
        $status = Get-AuthenticodeSignature $filePath
        Write-Output "[status] Signature Message: $($status.StatusMessage)"
    }
}

# define list of files to sign
$filesToSign = @(
    $GUI_JCADMU,
    $UWP_JCADMU
)
# Sign each PSModule file and EXEs
Write-Output "[status] Begin Signing Files:"
foreach ($file in $filesToSign) {
    Set-FileCertificate -passwd $password -alg "SHA256" -filePath $file -certFilePath $filenameCert
}
Write-Output "[status] Done signing binaries`n"
Write-Output "[status] Begin update of seccurity catalog"
# Re-Generate catalog now that the PSModule files have been signed
./PowerShell/Update-SecurityCatalog.ps1
Write-Output "[status] Security Catalog Update Complete`n"

Write-Output "[status] Begin Signing Catalog"
# Finally sign the catalog file after re-generation
Set-FileCertificate -passwd $password -alg "SHA256" -filePath $JCADMU_CAT -certFilePath $filenameCert
Write-Output "[status] Securty catalog signed!`n"