function Get-RegistryExeStatus {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter()]
        [System.Object]
        $resultsObject
    )
    # if resultsObject has an exception, the command failed:
    if ($resultsObject.Exception) {
        # write the warning
        Write-Warning "$($resultsObject.TargetObject)"
        Write-Warning "$($resultsObject.InvocationInfo.PositionMessage)"
        Error-Map -Error:("load_unload_error")

        # return false
        $status = $false
    } else {
        # return true
        $status = $true
    }
    # return true or false
    return $status
}