Function Test-SecurityIdentifier {
    param(
        [string]$SID
    )
    $profileList = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList").Name
    $sidList = New-Object System.Collections.ArrayList
    foreach ($item in $profileList) {
        $individualSid = $item | split-path -Leaf
        $sidList.Add($individualSid) | Out-Null

    }
    if ($sid -in $sidList) {
        return $true
    } else {
        return $false
    }
}