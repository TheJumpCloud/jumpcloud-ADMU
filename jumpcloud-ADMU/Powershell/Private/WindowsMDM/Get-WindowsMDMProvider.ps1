function Get-WindowsMDMProvider {
    [OutputType([System.Collections.ArrayList])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$MdmEnrollmentKey = 'HKLM:\SOFTWARE\Microsoft\Enrollments\'
    )
    begin {
        Write-ToLog "Checking for MDM Enrollment Key at: $MdmEnrollmentKey" -Step "Get-WindowsMDMProvider" -Level Verbose
        if (!(Test-Path $MdmEnrollmentKey)) {
            Write-ToLog "MDM enrollment key: '$MdmEnrollmentKey' not found." -Level Warning -Step "Get-WindowsMDMProvider"
            return # Exit the function if the base key doesn't exist
        }

        $enrollmentGuids = Get-ChildItem $MdmEnrollmentKey -ErrorAction SilentlyContinue
        if (!$enrollmentGuids) {
            Write-ToLog "MDM enrollment key exists at '$MdmEnrollmentKey', but no specific enrollment GUIDs (subkeys) were found under it." -Step "Get-WindowsMDMProvider" -Level Verbose
            return # Exit if no subkeys
        }
        Write-ToLog "MDM Enrollment Keys Found. Checking for ProviderID and UPN..." -Step "Get-WindowsMDMProvider" -Level Verbose
        # create a list to return results
        $enrollmentList = New-Object System.Collections.ArrayList
    }
    process {
        foreach ($guidItem in $enrollmentGuids) {
            if ($guidItem.PSChildName -match '^[A-Fa-f0-9]{8}-([A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}$') {
                $enrollmentPropertiesPath = $guidItem.PSPath
                $providerID = (Get-ItemProperty -Path $enrollmentPropertiesPath -Name 'ProviderID' -ErrorAction SilentlyContinue).ProviderID
                $upn = (Get-ItemProperty -Path $enrollmentPropertiesPath -Name 'UPN' -ErrorAction SilentlyContinue).UPN

                if ($providerID -and $upn) {
                    Write-ToLog "Found ProviderID '$providerID' and UPN '$upn' for enrollment $($guidItem.PSChildName)." -Step "Get-WindowsMDMProvider" -Level Verbose
                    # Output the object
                    $enrollmentList.Add([PSCustomObject]@{
                            EnrollmentGUID = $guidItem.PSChildName
                            ProviderID     = $providerID
                            UPN            = $upn
                        }) | Out-Null
                }
            } else {
                Write-ToLog "Skipping non-GUID subkey: $($guidItem.PSChildName)" -Step "Get-WindowsMDMProvider" -Level Verbose
            }
        }
    }
    end {
        return $enrollmentList
    }
}