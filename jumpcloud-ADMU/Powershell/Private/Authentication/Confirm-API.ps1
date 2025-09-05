function Confirm-API {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$jcApiKey,
        [Parameter(Mandatory = $false)]
        [string]$jcOrgID,
        [Parameter(Mandatory = $false)]
        [bool]$SystemContextBinding
    )

    begin {
        $results = [System.Collections.Generic.List[object]]::new()
    }

    process {
        # This block determines the result and stores it in the $confirmAPIResults variable.

        # 1. Check for SystemContext API eligibility first if requested.
        if ($SystemContextBinding) {
            $systemContextCheck = Invoke-SystemContextAPI -method 'GET' -endpoint 'systems'
            if ($systemContextCheck -and $systemContextCheck.id) {
                $confirmAPIResults = [PSCustomObject]@{
                    Type        = 'SystemContext'
                    IsValid     = $true
                    ValidatedID = $systemContextCheck.id
                }
            }
        } else {
            if (-not [string]::IsNullOrEmpty($jcApiKey)) {
                $testAPIResult = Test-APIKey -jcApiKey $jcApiKey -jcOrgId $jcOrgID
                Write-toLog -Message "Test-APIKey result: IsValid=$($testAPIResult.IsValid), ID=$($testAPIResult.ID)" -Level Verbose
                if ($testAPIResult.IsValid) {
                    # API key is valid
                    $confirmAPIResults = [PSCustomObject]@{
                        Type        = 'API'
                        IsValid     = $true
                        ValidatedID = $testAPIResult.ID
                    }
                } else {
                    # API key was provided but was not valid
                    $confirmAPIResults = [PSCustomObject]@{
                        Type        = 'API'
                        IsValid     = $false
                        ValidatedID = $null
                    }
                }
            } else {
                # 3. If no other method worked, this is the final failure case.
                $confirmAPIResults = [PSCustomObject]@{
                    Type        = 'None'
                    IsValid     = $false
                    ValidatedID = $null
                }
            }
        }

        $results.Add($confirmAPIResults)
    }

    end {
        # The end block's only job is to output the final result.
        return $results
    }
}