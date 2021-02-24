# This script is intended to be run from the Powershell Module on a local system
# If the JumpCloud agent is installed on AD Bound systems, all domain accounts
# can be queried for every system.

# Get Windows systems
$systems = Get-JCSystem -os "Windows"
# Define SID Pattern for users
$sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
# Get Users on systems
$all = @()
foreach ($system in $systems) {
    $all += Get-JCSystemInsights -Table User -SystemId $($system._id) | Where-Object { ($_.Directory -ne "") -AND ([regex]::IsMatch($($_.Uuid), $sidPattern)) -And ($_.Type -eq "roaming") }
}
$all | ConvertTo-Csv | Out-File "~/ADMU_EXPORT.CSV"
# Export CSV