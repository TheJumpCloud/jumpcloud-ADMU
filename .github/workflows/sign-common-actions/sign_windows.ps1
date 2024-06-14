function Invoke-Sign {
    param (
        $filesToSign,
        $isReleaseBuild
    )

    Write-Host "Signing files: $filesToSign"
    Write-Host "Is Release Build: $isReleaseBuild"

    # Add backup TSA Servers (RFC 3161) in case we get rate-limited
    $tsaServers = @(
        "http://timestamp.digicert.com",
        "http://sha256timestamp.ws.symantec.com/sha256/timestamp"
    )

    New-Variable -Name MaxAttempts -Option Constant -Value 5

    if ($isReleaseBuild -eq $true) {
        Write-Output "Signing with production Cert"
        $rootSubjectName = "DigiCert Trusted Root G4"
    } Else {
        Write-Output "Signing with development Cert"
        $rootSubjectName = "JumpCloud Root Private CA"
    }

    foreach ($file in $filesToSign) {
        $tsaIndex = 0
        $attempts = 1
        while ($True) {
            $filename = Split-Path $file -leaf

            Write-Output "attempting to sign $($filename) with $($tsaServers[$tsaIndex])"
            & "signtool.exe" sign `
                /d "$filename" `
                /r "$rootSubjectName" `
                /tr $($tsaServers[$tsaIndex]) `
                /td SHA256 `
                /fd SHA256 `
                $file

            if ( -not $? ) {
                if ($tsaIndex -lt $tsaServers.Count) {
                    Write-Output "trying a different TSA Server $($tsaServers[$tsaIndex])"
                    $tsaIndex++
                    Continue
                } Else {
                    if ($attempts -le $MaxAttempts) {
                        Write-Output "attempt $attempts failed, retrying..."
                        $attempts++
                        $tsaIndex = 0
                        Start-Sleep -Seconds 15
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
}

$ErrorActionPreference = "Stop"

if (!($env:INPUT_FILES)) {
    Write-Output "File list empty, no files to sign."
    Exit 0
}

# write the following out to null
smksp_registrar.exe list | Out-Null
smctl.exe keypair ls | Out-Null
C:\Windows\System32\certutil.exe -csp "DigiCert Signing Manager KSP" -key -user | Out-Null
smksp_cert_sync.exe | Out-Null

# invoke sign
Invoke-Sign $env:INPUT_FILES.Split([Environment]::Newline) $env:IS_RELEASE_BUILD
if (-not $?) { Exit 1 }