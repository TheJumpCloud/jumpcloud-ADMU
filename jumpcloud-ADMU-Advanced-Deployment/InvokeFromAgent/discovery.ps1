# Query Accounts based on Registry
$registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$profileList = @()
foreach ($profile in $registyProfiles)
{
    $profileList += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
}

$users = @()
foreach ($listItem in $profileList)
{
    $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
    $isValidFormat = [regex]::IsMatch($($listItem.PSChildName), $sidPattern);
    # Get Valid SIDs
    if ($isValidFormat)
    {
        # Populate Users List
        $users += [PSCustomObject]@{
            Name              = $listItem.PSChildName
            LocalPath         = $listItem.ProfileImagePath
            SID               = $listItem.PSChildName
        }
    }
}
$users | ConvertTo-Csv