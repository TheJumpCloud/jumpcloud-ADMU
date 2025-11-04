function Set-JCUserToSystemAssociation {
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$JcApiKey,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateLength(24, 24)][string]$JcOrgId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$JcUserID,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][bool]$BindAsAdmin,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$UserAgent
    )
    Begin {
        $windowsDrive = Get-WindowsDrive
        $config = get-content "$WindowsDrive\Program Files\JumpCloud\Plugins\Contrib\jcagent.conf"
        $regex = 'systemKey\":\"(\w+)\"'
        $systemKey = [regex]::Match($config, $regex).Groups[1].Value
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        If (!$systemKey) {
            Write-ToLog -Message:("Could not find systemKey, aborting bind step") -Level Warning -Step "Set-JCUserToSystemAssociation"
        }
    }
    Process {
        Write-ToLog -Message:("User matched in JumpCloud") -Level Verbose -Step "Set-JCUserToSystemAssociation"
        $Headers = @{
            'Accept'       = 'application/json';
            'Content-Type' = 'application/json';
            'x-api-key'    = $JcApiKey;
            'x-org-id'     = $JcOrgId;
        }
        $Form = @{
            'op'   = 'add';
            'type' = 'system';
            'id'   = "$systemKey"
        }
        if ($BindAsAdmin) {
            Write-ToLog -Message:("Bind As Admin specified. Setting sudo attributes for userID: $JcUserID") -Level Verbose -Step "Set-JCUserToSystemAssociation"
            $Form.Add("attributes", @{
                    "sudo" = @{
                        "enabled"         = $true
                        "withoutPassword" = $false
                    }
                }
            )
        } else {
            Write-ToLog -Message:("Bind As Admin NOT specified. userID: $JcUserID will be bound as a standard user") -Level Verbose -Step "Set-JCUserToSystemAssociation"
        }
        $jsonForm = $Form | ConvertTo-Json
        Try {
            Write-ToLog -Message:("Attempting to bind userID: $JcUserID to systemID: $systemKey") -Level Verbose -Step "Set-JCUserToSystemAssociation"
            $Response = Invoke-WebRequest -Method 'Post' -Uri "$($global:JCUrl)/api/v2/users/$JcUserID/associations" -Headers $Headers -Body $jsonForm -UseBasicParsing -UserAgent $UserAgent
            $StatusCode = $Response.StatusCode
        } catch {
            $errorMsg = $_.Exception.Message
            $StatusCode = $_.Exception.Response.StatusCode.value__
            Write-ToLog -Message:("Could not bind user to system") -Level Warning -Step "Set-JCUserToSystemAssociation"
        }

    }
    End {
        # Associations post should return 204 success no content
        if ($StatusCode -eq 204) {
            Write-ToLog -Message:("Associations Endpoint returned statusCode $statusCode [success]") -Level Warning -Step "Set-JCUserToSystemAssociation"
            return $true
        } else {
            Write-ToLog -Message:("Associations Endpoint returned statusCode $statusCode | $errorMsg") -Level Warning -Step "Set-JCUserToSystemAssociation"
            return $false
        }
    }
}
