
function Confirm-API {
    <#
    .SYNOPSIS
    Determines if the system is eligible for SystemContextAPI or standard API updates.

    .DESCRIPTION
    Checks for SystemContext API eligibility. If the system is eligible, it returns a success status for that type.
    If the system is not eligible for SystemContext and an API key is provided, it validates the API key.
    The function returns an object indicating the validation type ('SystemContext', 'API', or 'None') and a boolean status.

    .PARAMETER ApiKey
    An optional API key to be validated if the system is not eligible for SystemContext API.

    .PARAMETER SystemContextBinding
    An optional switch to indicate a preference for system context binding. The function currently runs its checks regardless of this parameter's presence.

    .EXAMPLE
    PS C:\> Confirm-API
    # Checks for SystemContext eligibility. If not found, returns valid = $false because no API key was provided.

    .EXAMPLE
    PS C:\> Confirm-API -ApiKey "jc_api_key_xxxxxxxxxx"
    # Checks for SystemContext eligibility. If not found, it proceeds to validate the provided API key.

    .RETURNS
    A custom PSObject with two properties:
    - type: Indicates the validation method ('SystemContext', 'API', 'None').
    - valid: A boolean ($true or $false) indicating if the method is available and valid.
    #>
    param (
        # Optional: The API key for validation if SystemContext is not available.
        [Parameter(Mandatory = $false)]
        [string]$JumpCloudApiKey,
        [Parameter(Mandatory = $false)]
        [string]$JumpCloudOrgID,
        [Parameter(Mandatory = $false)]
        [bool]$SystemContextBinding
    )

    # Check for SystemContext API eligibility first.
    if ($SystemContextBinding) {
        $systemContextCheck = Invoke-SystemContextAPI -method 'GET' -endpoint 'systems'
        if ($systemContextCheck -and $systemContextCheck.id) {
            $validatedSystemID = $systemContextCheck.id
            Write-ToLog "System is eligible for SystemContext API."
            return @{ type = 'SystemContext'; valid = $true; validatedSystemID = $validatedSystemID }
        } else {
            $validatedSystemContextAPI = $false
            Write-ToLog "[status] The systemContext API is not available for this system, please use the standard binding method"
            Write-ToLog "Checking for API key..."
        }
    }

    # If not eligible for SystemContext, check for a provided API key.
    Write-ToLog "System is not eligible for SystemContext API. Checking for API Key" -Level Warn
    if (-not [string]::IsNullOrEmpty($jumpCloudApiKey)) {
        # Validate the provided API key.
        # Get the systemId from the jcconfig file then pass to test-ApiKey
        $isApiKeyValid, $validatedSystemID = Test-APIKey -ApiKey $JumpCloudApiKey -orgId $JumpCloudOrgID
        if ($isApiKeyValid) {
            Write-ToLog "Provided API key is valid."
            return @{ type = 'API'; valid = $true; validatedSystemID = $validatedSystemID }
        } else {
            Write-ToLog "Provided API key is not valid." -level Warn
            return @{ type = 'API'; valid = $false }
        }
    }

    # If not SystemContext eligible and no valid API key is provided, return false.
    Write-ToLog "System is not eligible for SystemContext and no valid API key was provided." -level Warn
    return @{ type = 'API'; valid = $false }
}
