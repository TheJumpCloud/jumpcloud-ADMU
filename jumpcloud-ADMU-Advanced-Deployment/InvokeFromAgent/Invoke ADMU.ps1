# Variables
# If system is domain bound, $SelectedUsername can be "Domain\userToConvert"
# Else, enter the SID of the user to Convert
$SelectedUsername = ""
# Enter the username of the JumpCloud User
$JumpCloudUserName = ""
$TempPassword = "Temp123!Temp123!"
$AcceptEULA = [System.Convert]::ToBoolean('true')
$LeaveDomain = [System.Convert]::ToBoolean('true')
$ConvertProfile = [System.Convert]::ToBoolean('true')
$AzureADProfile = [System.Convert]::ToBoolean('false')

# Query User Sessions
$quserResult = quser
$quserRegex = $quserResult | ForEach-Object -Process { $_ -replace '\s{2,}', ',' }
$quserObject = $quserRegex | ConvertFrom-Csv

# If the username of logged in user matches the profile path of the user we want
# to migrate, log them off.
If ($quserObject.username)
{
    # TODO: Logout if match
    logoff.exe $quserObject.ID
}
# Kick off the ADMU with the SID from the selected user.
Start-Migration -JumpCloudUserName $JumpCloudUserName -SelectedUserName $SelectedUsername -TempPassword $TempPassword -AcceptEULA $AcceptEULA -LeaveDomain $LeaveDomain -ConvertProfile $ConvertProfile -AzureADProfile $AzureADProfile

# Restart Comptuer to update UI at login screen
Restart-Computer -Force