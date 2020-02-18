$signpath = 'C:\tools\signtool.exe'
$GUI_JCADMU = 'C:\agent\_work\1\s\exe\gui_jcadmu.exe'
$certdir = 'C:\agent\_work\_temp\'
$certFileName = "godaddy_windows_signing_cert.pfx"
$certPasswordFileName = "godaddy_windows_signing_cert_password.txt"
$certPath = Join-Path $certDir $certFileName
$passwordfile = $certdir + $certPasswordFileName
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
    $GUI_JCADMU
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
            /tr $($tsaServers[$tsaIndex]) `
            /td SHA256 `
            $file

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