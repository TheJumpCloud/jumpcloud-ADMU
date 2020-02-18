Param(
[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateNotNullOrEmpty()][System.String]$cert_pw_key
)


#test cert password
#$passwordfile = 'C:\tools\cert\test_windows_signing_cert_password.txt'


#vars
#$certpath = 'c:\tools\cert\test2.pfx'
$signpath = 'C:\tools\signtool.exe'
$GUI_JCADMU = 'C:\agent\_work\1\s\exe\gui_jcadmu.exe'
$certdir = 'C:\agent\_work\_temp\'
$certFileName = "godaddy_windows_signing_cert.pfx"
$certPasswordFileName = "godaddy_windows_signing_cert_password.txt"
$certPath = Join-Path $certDir $certFileName
$passwordfile = $certdir + $certPasswordFileName
$password = Get-Content $passwordfile -Raw



# call this function when we exit the script in order to remove the decrypted certificate files:
function cleanupCertFiles {
    #Remove-Item $certdir\$certFileName
    #Remove-Item $certdir\$certPasswordFileName
}

#signing Steps

Write-Output "Signing binaries"

#Decrypt certificate files
#secure-file\tools\secure-file -decrypt $certdir\$certPasswordFileName.enc -secret $cert_pw_key
#secure-file\tools\secure-file -decrypt $certdir\$certFileName.enc -secret $cert_pw_key

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
                    cleanupCertFiles
                    Exit 1
                }
            }
        }
        Else {
            Break
        }
    }
}

cleanupCertFiles
Write-Output "Done signing binaries"