Param(
[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][ValidateNotNullOrEmpty()][System.String]$GitHubAccessToken
)

$RootPath = $PSScriptRoot
$Output = $RootPath + '\ADMU.ps1'
# Clear existing file
If (Test-Path -Path:($Output)) { Remove-Item -Path:($Output) }

# Get file contents
$StartJCADMU = (Get-Content -Path:($RootPath + '\Start-JCADMU.ps1') -Raw) -Replace ("`r", "")
$Functions = (Get-Content -Path:($RootPath + '\Functions.ps1') -Raw) -Replace ("`r", "")
$Form = (Get-Content -Path:($RootPath + '\Form.ps1') -Raw) -Replace ("`r", "")
# String manipulation
$NewContent = $StartJCADMU
$NewContent = $NewContent.Replace('# Get script path' + "`n", '')
$NewContent = $NewContent.Replace('$scriptPath = (Split-Path -Path:($MyInvocation.MyCommand.Path))' + "`n", '')
$NewContent = $NewContent.Replace('& ($scriptPath + ''\Functions.ps1'')', $Functions)
$NewContent = $NewContent.Replace('$formResults = Invoke-Expression -Command:(''& "'' + $scriptPath + ''\Form.ps1"'')' + "`n", $Form)
$NewContent = $NewContent.Replace('Return $FormResults' + "`n" + '}', '')
$NewContent = $NewContent + "`n" + '}'
$NewContent = $NewContent -split "`n" | ForEach-Object { If ($_.Trim()) { $_ } }
# Export combined file
$NewContent | Out-File -FilePath:($Output)

#Build exe
$guiversion = (select-string -InputObject (get-item 'C:\agent\_work\1\s\powershell\Form.ps1') -Pattern "Title=").ToString()
$formversion = $guiversion.Substring(69,5)

& "C:\tools\PS2EXE-GUI\ps2exe.ps1" -inputFile 'C:\agent\_work\1\s\powershell\ADMU.ps1' -outputFile 'C:\agent\_work\1\s\exe\gui_jcadmu.exe' -runtime40 -title 'JumpCloud ADMU' -product 'JumpCloud ADMU' -description 'JumpCloud AD Migration Utility' -copyright '(c) 2020' -version $formversion -company 'JumpCloud' -requireAdmin

#$GitHubAccessToken = '' #Created in GitHub. Token must have the Scopes "repo Full control of private repositories" checked.
$GitHubHeaders = @{
    'Authorization' = 'token ' + $GitHubAccessToken
    'Accept'        = 'application/vnd.github.v3.raw'
}
$LatestRelease = Invoke-RestMethod -Method:('GET') -Uri:('https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases') -Headers:($GitHubHeaders)
# $LatestRelease = Invoke-RestMethod -Method:('GET') -Uri:('https://api.github.com/repos/TheJumpCloud/jumpcloud-ADMU/releases/latest') -Headers:($GitHubHeaders)
$LatestRelease


#Sign exe
$cert_key =
$cert_pw_key =
$GUI_JCADMU = "C:\agent\_work\1\s\exe\gui_jcadmu.exe"

# call this function when we exit the script in order to remove the decrypted certificate files:
function cleanupCertFiles {
    del $certdir\$certFileName
    del $certdir\$certPasswordFileName
}

if ( -not $env:cert_key ) {
    Write-Output "Not in a production build, so not signing agent binaries"
}
else {
    Write-Output "Signing agent, credential provider dll, and jccli binaries"
    # If you want to sign the installer locally with this script, you will need to set the $cert_key and $cert_pw_key
    # env variables before running this script. The keys in appveyor.yml are encrypted so you'll need
    # to either obtain the unencrypted keys or just obtain a copy of the certificate/password itself and do the signing manually.
    # In Powershell use the following command to set an environment variable:
    # $env:cert_key = "YOUR_CERT_KEY_VALUE"
    # You will also need to install the secure-file tool in order to decrypt the certificate files: https://www.appveyor.com/docs/how-to/secure-files/

    $certdir = "c:\tools\cert"
    $certFileName = "godaddy_windows_signing_cert.pfx"
    $certPasswordFileName = "godaddy_windows_signing_cert_password.txt"

    secure-file\tools\secure-file -decrypt $certdir\$certPasswordFileName.enc -secret $env:cert_pw_key
    secure-file\tools\secure-file -decrypt $certdir\$certFileName.enc -secret $env:cert_key
    $password = Get-Content $certdir\$certPasswordFileName -Raw

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
            & "C:\tools\signtool.exe" sign `
                /f $certdir\$certFileName `
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

    Write-Output "Done signing binaries"
}
