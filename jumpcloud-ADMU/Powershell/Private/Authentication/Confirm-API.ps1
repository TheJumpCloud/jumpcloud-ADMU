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
        # this function will return the following object
        $confirmAPIResults = [PSCustomObject]@{
            Type        = $null
            IsValid     = $false
            ValidatedID = $null
        }
    }
    process {
        # 1. Check for SystemContext API eligibility first if requested.
        if ($SystemContextBinding) {
            $systemContextCheck = Invoke-SystemContextAPI -method 'GET' -endpoint 'systems'
            if ($systemContextCheck -and $systemContextCheck.id) {
                # set the return object
                $confirmAPIResults.Type = 'SystemContext'
                $confirmAPIResults.IsValid = $true
                $confirmAPIResults.ValidatedID = $systemContextCheck.id
                return
            }
        }
        # 2. Next, if an API key was provided, test it.
        if (-not [string]::IsNullOrEmpty($jcApiKey)) {
            $testAPIResult = Test-APIKey -jcApiKey $jcApiKey -jcOrgId $jcOrgID
            Write-toLog -Message "Test-APIKey result: IsValid=$($testAPIResult.IsValid), ID=$($testAPIResult.ID)" -Level Verbose
            if ($testAPIResult.IsValid) {
                # API key is valid
                # set the return object
                $confirmAPIResults.Type = 'API'
                $confirmAPIResults.IsValid = $true
                $confirmAPIResults.ValidatedID = $testAPIResult.ID
                return
            }
        } else {
            # API key was provided but was not valid
            $confirmAPIResults.Type = 'API'
            $confirmAPIResults.IsValid = $false
            $confirmAPIResults.ValidatedID = $null
            return
        }
        # 3. If no other method worked, this is the final failure case.
        $confirmAPIResults.Type = 'None'
        $confirmAPIResults.IsValid = $false
        $confirmAPIResults.ValidatedID = $null
        return
    }
    end {
        return $confirmAPIResults
    }
}