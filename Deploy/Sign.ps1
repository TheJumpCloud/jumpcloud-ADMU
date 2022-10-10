

# Begin setup Steps

# Sign Variables
$signpath = 'C:/Program Files (x86)/Windows Kits/10/bin/10.0.17763.0/x86/signtool.exe'
$RootPath = Split-Path (Split-Path $PSScriptRoot -Parent)
$GUI_JCADMU = "$RootPath/jumpcloud-ADMU/jumpcloud-ADMU/Exe/gui_jcadmu.exe"
$UWP_JCADMU = "$RootPath/jumpcloud-ADMU/jumpcloud-ADMU/Exe/uwp_jcadmu.exe"
$base64 = "$env:BASE64_ENCODED_CERT"
$password = "$env:CERTPASS"
$filenameCert = "$PSScriptRoot/cert.pfx"
$bytes = [convert]::FromBase64String($base64)
[IO.File]::WriteAllBytes($filenameCert, $bytes)



if (test-path($filenameCert))
{
    Write-Output "Cert found"
}
else
{
    Write-Output "Cert not found, exiting"
    exit 1
}
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


foreach ($file in $filesToSign)
{
    If (Test-Path -Path ($file))
    {
        Write-Output "Attempting to sign $file"
    }
    else
    {
        Write-Output "$file not found"
        exit 1
    }

    $tsaIndex = 0
    $attempts = 1
    while ($True)
    {
        Write-Output "attempting to sign with $($tsaServers[$tsaIndex])"
        & $signpath sign `
            /f $filenameCert `
            /fd SHA256 `
            /p $password `
            /tr http://timestamp.digicert.com `
            $file

        if ( -not $? )
        {
            if ($attempts -le $MaxAttempts)
            {
                Write-Output "attempt $attempts failed, retrying..."
                $attempts++
                Start-Sleep -Seconds 15
                Continue
            }
            Else
            {
                if ($tsaIndex -lt $tsaServers.Count)
                {
                    Write-Output "trying a different TSA Server $($tsaServers[$tsaIndex])"
                    $tsaIndex++
                    $attempts = 1
                    Continue
                }
                Else
                {
                    Write-Output "Failed to sign $file, error=$error"
                    Exit 1
                }
            }
        }
        Else
        {
            Break
        }
    }
}

Write-Output "Done signing binaries"