function DenyInteractiveLogonRight {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        $SID
    )
    process {
        # Add migrating user to deny logon rights
        $secpolFile = "C:\Windows\temp\ur_orig.inf"
        if (Test-Path $secpolFile) {
            Remove-Item $secpolFile -Force
        }
        secedit /export /areas USER_RIGHTS /cfg C:\Windows\temp\ur_orig.inf
        $secpol = (Get-Content $secpolFile)
        $regvaluestring = $secpol | Where-Object { $_ -like "*SeDenyInteractiveLogonRight*" }
        $regvaluestringID = [array]::IndexOf($secpol, $regvaluestring)
        $oldvalue = (($secpol | Select-String -Pattern 'SeDenyInteractiveLogonRight' | Out-String).trim()).substring(30)
        $newvalue = ('*' + $SID + ',' + $oldvalue.trim())
        $secpol[$regvaluestringID] = 'SeDenyInteractiveLogonRight = ' + $newvalue
        $secpol | out-file $windowsDrive\Windows\temp\ur_new.inf -force
        secedit /configure /db secedit.sdb /cfg $windowsDrive\Windows\temp\ur_new.inf /areas USER_RIGHTS
    }
}