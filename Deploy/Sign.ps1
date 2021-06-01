# Begin setup Steps

# Setup Cert Directory
$CertDirectory = "C:\cert\"
if (!(Test-Path "$CertDirectory"))
{
    new-item -path $CertDirectory -ItemType Directory
}
# Setup SecretHub
Invoke-WebRequest https://get.secrethub.io/windows | Invoke-Expression
secrethub --version
secrethub credential ls
secrethub read --out-file $CertDirectory/godaddy_windows_signing_cert.pfx JumpCloud/github/godaddy-windows-signing-cert-pfx
secrethub read --out-file $CertDirectory/godaddy_windows_signing_cert.txt JumpCloud/github/godaddy-windows-signing-cert-txt


# Sign Variables
$signpath = 'C:\tools\signtool.exe'
$GUI_JCADMU = ("$PSScriptRoot/../jumpcloud-ADMU/Exe/gui_jcadmu.exe")
$UWP_JCADMU = ("$PSScriptRoot/../jumpcloud-ADMU/Exe/uwp_jcadmu.exe")

# End Setup Steps
$certFileName = "godaddy_windows_signing_cert.pfx"
$certPasswordFileName = "godaddy_windows_signing_cert_password.txt"
$certPath = Join-Path $CertDirectory $certFileName
$passwordfile = $CertDirectory + $certPasswordFileName
$password = Get-Content $passwordfile -Raw

Write-Output "Signing binaries"

New-Variable -Name MaxAttempts -Option Constant -Value 5

# Add backup TSA Servers (RFC 3161) in case we get rate-limited
$tsaServers = @(
    "http://tsa.starfieldtech.com",
    "https://timestamp.geotrust.com/tsa",
    "http://timestamp.apple.com/ts01"
)

$filesToSign = @(
    $GUI_JCADMU,
    $UWP_JCADMU
)

foreach ($file in $filesToSign) {
    $tsaIndex = 0
    $attempts = 1
    while ($True) {
        Write-Output "attempting to sign with $($tsaServers[$tsaIndex])"
        & $signpath sign `
            /f $certpath `
            /fd SHA256 `
            /p $password `
            $file

            #move above $file for tsachecks
            #/tr $($tsaServers[$tsaIndex]) `
            #/td SHA256 `

        if ( -not $? ) {
            if ($attempts -le $MaxAttempts) {
                Write-Output "attempt $attempts failed, retrying..."
                $attempts++
                Start-Sleep -Seconds 15
                Continue
            }
            Else {
                if ($tsaIndex -lt $tsaServers.Count) {
                    Write-Output "trying a different TSA Server $($tsaServers[$tsaIndex])"
                    $tsaIndex++
                    $attempts = 1
                    Continue
                }
                Else {
                    Write-Output "Failed to sign $file, error=$error"
                    Exit 1
                }
            }
        }
        Else {
            Break
        }
    }
}

Write-Output "Done signing binaries"
