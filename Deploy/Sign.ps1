

# Begin setup Steps

# Sign Variables
$signpath = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.17763.0/x86/signtool.exe'
$RootPath = Split-Path (Split-Path $PSScriptRoot -Parent)
$GUI_JCADMU = "$RootPath\jumpcloud-ghactions-testing\jumpcloud-ghactions-testing\gui_jcadmu_unsigned.exe"
$UWP_JCADMU = "$RootPath\jumpcloud-ghactions-testing\jumpcloud-ghactions-testing\uwp_jcadmu_unsigned.exe"

Write-Output "Signing binaries"
New-Variable -Name MaxAttempts -Option Constant -Value 5

# Add backup TSA Servers (RFC 3161) in case we get rate-limited
$tsaServers = @(
    "http://timestamp.digicert.com",
    "http://sha256timestamp.ws.symantec.com/sha256/timestamp"
)

$filesToSign = @(
    $GUI_JCADMU,
    $UWP_JCADMU
)

Write-Output "Signing with Production Cert"
$codeSigningCertHash = $env:SM_CODE_SIGNING_CERT_SHA1_HASH


foreach ($file in $filesToSign) {
    If (Test-Path -Path ($file)) {
        Write-Output "Attempting to sign $file"
    } else {
        Write-Output "$file not found"
        exit 1
    }

    $tsaIndex = 0
    $attempts = 1
    while ($True) {
        $filename = Split-Path $file -leaf

        Write-Output "attempting to sign with $($tsaServers[$tsaIndex])"
        # new
        & $signpath sign `
            /d "$filename" `
            /sha1 $codeSigningCertHash `
            /tr $($tsaServers[$tsaIndex]) `
            /td SHA256 `
            /fd SHA256 `
            $file

        if ( -not $? ) {
            if ($attempts -le $MaxAttempts) {
                Write-Output "attempt $attempts failed, retrying..."
                $attempts++
                Start-Sleep -Seconds 15
                Continue
            } Else {
                if ($tsaIndex -lt $tsaServers.Count) {
                    Write-Output "trying a different TSA Server $($tsaServers[$tsaIndex])"
                    $tsaIndex++
                    $attempts = 1
                    Continue
                } Else {
                    Write-Output "Failed to sign $file, error=$error"
                    Exit 1
                }
            }
        } Else {
            Break
        }
    }
}

Write-Output "Done signing binaries"