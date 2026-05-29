function Test-SkipMdmEnrollment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EnrollmentGUID,
        [Parameter(Mandatory = $false)]
        [array]$Enrollments
    )
    if ($Enrollments) {
        $enrollment = $Enrollments | Where-Object { $_.EnrollmentGUID -eq $EnrollmentGUID }
        if ($enrollment -and $enrollment.ProviderID -like '*JumpCloud*') {
            return $true
        }
    }
    $regPath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$EnrollmentGUID"
    if (Test-Path $regPath) {
        $providerId = Get-ItemProperty -LiteralPath $regPath -Name 'ProviderID' -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty ProviderID -ErrorAction SilentlyContinue
        if ($providerId -like '*JumpCloud*') {
            return $true
        }
    }
    return $false
}
