function Get-WindowsMDMProvider {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$MdmEnrollmentKey = 'HKLM:\SOFTWARE\Microsoft\Enrollments\'
    )

    Write-ToLog "Checking for MDM Enrollment Key at: $MdmEnrollmentKey"
    if (!(Test-Path $MdmEnrollmentKey)) {
        Write-ToLog "MDM enrollment key: '$MdmEnrollmentKey' not found." -Level Warn
        return
    }

    $enrollmentGuids = Get-ChildItem $MdmEnrollmentKey -ErrorAction SilentlyContinue
    if (!$enrollmentGuids) {
        Write-ToLog "MDM enrollment key exists, but no specific enrollment GUIDs were found."
        return
    }

    $foundDetails = $false
    # We only care about subkeys that look like GUIDs and have actual data (ProviderID/UPN)
    foreach ($guidItem in $enrollmentGuids) {
        if ($guidItem.PSChildName -match '^[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$') {
            $enrollmentPropertiesPath = $guidItem.PSPath
            $providerID = (Get-ItemProperty -Path $enrollmentPropertiesPath -Name 'ProviderID' -ErrorAction SilentlyContinue).ProviderID
            $upn = (Get-ItemProperty -Path $enrollmentPropertiesPath -Name 'UPN' -ErrorAction SilentlyContinue).UPN

            if ($providerID -and $upn) {
                Write-ToLog "Found ProviderID '$providerID' and UPN '$upn' for enrollment $($guidItem.PSChildName)."
                [PSCustomObject]@{
                    EnrollmentGUID = $guidItem.PSChildName
                    ProviderID     = $providerID
                    UPN            = $upn
                }
                $foundDetails = $true
            }
        }
    }
    if (-not $foundDetails) {
        Write-ToLog "No enrollments found with both ProviderID and UPN under '$MdmEnrollmentKey'."
        return $null
    }
}