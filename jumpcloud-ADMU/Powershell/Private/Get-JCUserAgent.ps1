function Get-JCUserAgent {
    param (
    [Parameter(Mandatory=$true)]
    [System.Boolean]$isForm
)#[ValidateSet('JumpCloud_ADMU.Application', 'JumpCloud_ADMU.PowerShellModule')]

    if ($isForm) {
        $useragent = 'JumpCloud_ADMU.Application'
    } else {
        $UserAgent = 'JumpCloud_ADMU.PowerShellModule'
    }
    $UserAgent_ModuleVersion = '2.7.0'
    #Build the UserAgent string
    $Template_UserAgent = "{0}/{1}"
    $customUserAgent = $Template_UserAgent -f $UserAgent, $UserAgent_ModuleVersion
    Write-Host "UserAgent: $customUserAgent"
    return $customUserAgent
}
