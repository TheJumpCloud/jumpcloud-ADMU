Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Loading ADMU GUI..'

#==============================================================================================
# XAML Code - Imported from Visual Studio WPF Application
#==============================================================================================
[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[xml]$XAML = @'
<Window
     xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
     xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
     Title="JumpCloud ADMU 1.2.16" Height="626.734" Width="1017.775" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" ForceCursor="True">
    <Grid Margin="0,0,4,0">
        <ListView Name="lvProfileList" HorizontalAlignment="Left" Height="230" Margin="10,224,0,0" VerticalAlignment="Top" Width="975">
            <ListView.View>
                <GridView>
                    <GridViewColumn Header="System Accounts" DisplayMemberBinding="{Binding 'UserName'}" Width="180"/>
                    <GridViewColumn Header="Last Login" DisplayMemberBinding="{Binding 'LastLogin'}" Width="135"/>
                    <GridViewColumn Header="Currently Active" DisplayMemberBinding="{Binding 'Loaded'}" Width="105" />
                    <GridViewColumn Header="Domain Roaming" DisplayMemberBinding="{Binding 'RoamingConfigured'}" Width="105"/>
                    <GridViewColumn Header="Local Admin" DisplayMemberBinding="{Binding 'IsLocalAdmin'}" Width="105"/>
                    <GridViewColumn Header="Local Path" DisplayMemberBinding="{Binding 'LocalPath'}" Width="140"/>
                    <GridViewColumn Header="Local Profile Size" DisplayMemberBinding="{Binding 'LocalProfileSize'}" Width="105"/>

                </GridView>
            </ListView.View>
        </ListView>
        <Button Name="bDeleteProfile" Content="Select Profile" HorizontalAlignment="Left" Margin="833,557,0,0" VerticalAlignment="Top" Width="121" Height="23" IsEnabled="False">
            <Button.Effect>
                <DropShadowEffect/>
            </Button.Effect>
        </Button>
        <GroupBox Header="System Information" HorizontalAlignment="Left" Height="116" Margin="10,103,0,0" VerticalAlignment="Top" Width="341" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="90" VerticalAlignment="Top" Width="319">
                <Label Content="Local Computer Name:" HorizontalAlignment="Left" Margin="10,2.56,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Content="USMT Detected:" HorizontalAlignment="Left" Margin="10,29,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbComputerName" Content="" HorizontalAlignment="Left" Margin="141,4,0,0" VerticalAlignment="Top" Width="166" FontWeight="Normal"/>
                <Label Name="lbUSMTStatus" Content="" HorizontalAlignment="Left" Margin="143,30,0,0" VerticalAlignment="Top" Width="166" FontWeight="Normal"/>
                <Label Content="C:\ Free Disk Space:" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbcfreespace" Content="" HorizontalAlignment="Left" Margin="144,57,0,0" VerticalAlignment="Top" Width="166" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="Account Migration Information" HorizontalAlignment="Left" Height="92" Margin="514,459,0,0" VerticalAlignment="Top" Width="471" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="66.859" Margin="1.212,2.564,0,0" VerticalAlignment="Top" Width="454.842">
                <Label Content="Local Account Username :" HorizontalAlignment="Left" Margin="7.088,8.287,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Content="Local Account Password :" HorizontalAlignment="Left" Margin="7.088,36.287,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <TextBox Name="tbJumpCloudUserName" HorizontalAlignment="Left" Height="23" Margin="151.11,10.287,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="301.026" Text="Username should match JumpCloud username" Background="#FFC6CBCF" FontWeight="Bold" />
                <TextBox Name="tbTempPassword" HorizontalAlignment="Left" Height="23" Margin="151.11,39.287,0,0" TextWrapping="Wrap" Text="Temp123!" VerticalAlignment="Top" Width="301.026" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="System Migration Options" HorizontalAlignment="Left" Height="93" Margin="10,459,0,0" VerticalAlignment="Top" Width="498" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="62.124" Margin="1.888,2.564,0,0" VerticalAlignment="Top" Width="456.049">
                <Label Name="lbMoreInfo" Content="More Info" HorizontalAlignment="Left" Margin="91.649,38,0,-0.876" VerticalAlignment="Top" Width="65.381" FontSize="11" FontWeight="Bold" FontStyle="Italic" Foreground="#FF005DFF"/>
                <CheckBox Name="cb_accepteula" Content="Accept EULA" HorizontalAlignment="Left" Margin="3.649,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="True"/>
                <Label Content="JumpCloud Connect Key :" HorizontalAlignment="Left" Margin="3.649,7.999,0,0" VerticalAlignment="Top" AutomationProperties.HelpText="https://console.jumpcloud.com/#/systems/new" ToolTip="https://console.jumpcloud.com/#/systems/new" FontWeight="Normal"/>
                <TextBox Name="tbJumpCloudConnectKey" HorizontalAlignment="Left" Height="23" Margin="148.673,10,0,0" TextWrapping="Wrap" Text="Enter JumpCloud Connect Key" VerticalAlignment="Top" Width="301.026" Background="#FFC6CBCF" FontWeight="Bold"/>
                <CheckBox Name="cb_installjcagent" Content="Install JCAgent" HorizontalAlignment="Left" Margin="155.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="True"/>
                <CheckBox Name="cb_leavedomain" Content="Leave Domain" HorizontalAlignment="Left" Margin="258.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_forcereboot" Content="Force Reboot" HorizontalAlignment="Left" Margin="359.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="Migration Steps" HorizontalAlignment="Left" Height="98" Margin="10,0,0,0" VerticalAlignment="Top" Width="975" FontWeight="Bold">
            <TextBlock HorizontalAlignment="Left" TextWrapping="Wrap" VerticalAlignment="Top" Height="70" Width="561" Margin="0,10,0,-5" FontWeight="Normal"><Run Text="1. Select the domain or AzureAD account that you want to migrate to a local account from the list below."/><LineBreak/><Run Text="2. Enter a local account username and password to migrate the selected account to. "/><LineBreak/><Run Text="3. Enter your organizations JumpCloud system connect key."/><LineBreak/><Run Text="4. Click the "/><Run Text="Migrate Profile"/><Run Text=" button."/><LineBreak/><Run/></TextBlock>
        </GroupBox>
        <GroupBox Header="Domain Information" HorizontalAlignment="Left" Height="116" Margin="356,103,0,0" VerticalAlignment="Top" Width="321" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="151" Margin="10,0,0,-58" VerticalAlignment="Top" Width="297">
                <Label Content="Domain Name:" HorizontalAlignment="Left" Margin="-3,1,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbDomainName" Content="" Margin="120,-3,10,107" Foreground="Black" FontWeight="Normal"/>
                <Label Content="Secure Channel Healthy:" HorizontalAlignment="Left" Margin="-3,54,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbsecurechannel" Content="" HorizontalAlignment="Left" Margin="131,56,0,0" VerticalAlignment="Top" Width="166" FontWeight="Normal"/>
                <Label Content="NetBios Name:" HorizontalAlignment="Left" Margin="-3,26,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbNetBios" Content="" Margin="121,22,9,82" Foreground="Black" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="AzureAD Information" HorizontalAlignment="Left" Height="116" Margin="682,103,0,0" VerticalAlignment="Top" Width="303" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="156" Margin="10,0,0,-63" VerticalAlignment="Top" Width="297">
                <Label Content="AzureAD Joined:" HorizontalAlignment="Left" Margin="-3,9,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbAzureAD_Joined" Content="" Margin="120,6,10,98" Foreground="Black" FontWeight="Normal"/>
                <Label Content="Workplace Joined:" HorizontalAlignment="Left" Margin="-3,28,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbWorkplace_Joined" Content="" Margin="119,25,11,79" Foreground="Black" FontWeight="Normal"/>
                <Label Content="Tenant Name:" HorizontalAlignment="Left" Margin="-3,52,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbTenantName" Content="" Margin="120,48,10,56" Foreground="Black" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
    </Grid>
</Window>
'@

# Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
Try
{
    $Form = [Windows.Markup.XamlReader]::Load($reader)
}
Catch
{
    Write-Error "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered.";
    Exit;
}
#===========================================================================
# Store Form Objects In PowerShell
#===========================================================================
$xaml.SelectNodes("//*[@Name]") | ForEach-Object { Set-Variable -Name ($_.Name) -Value $Form.FindName($_.Name) }

# Define misc static variables
        $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
        $AzureADInfo = Get-DSregcmdstatus
        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Checking AzureAD Status..'

        if ($WmiComputerSystem.PartOfDomain) {
            $WmiComputerDomain = Get-WmiObject -Class:('Win32_ntDomain')
            $DomainName = $WmiComputerDomain.DnsForestName
            $NetBiosName = $WmiComputerDomain.DomainName
            $securechannelstatus = Test-ComputerSecureChannel
        }
        else {
            $DomainName = 'N/A'
            $NetBiosName = 'N/A'
            $securechannelstatus = 'N/A'
        }

        if (($AzureADInfo.Status[0] -eq 'YES')) {
            $AzureADStatus = $true
            $Workplace_join = $AzureADInfo.status[2]
            $TenantName = $AzureADInfo[24]
        }
        else {
            $AzureADStatus = 'N/A'
            $Workplace_join = 'N/A'
            $TenantName = 'N/A'
        }
        $FormResults = [PSCustomObject]@{ }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Getting Installed Applications..'

        $InstalledProducts = (Get-WmiObject -Class:('Win32_Product') | Select-Object Name)
        $Disk = Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"
        $freespace = $Disk.FreeSpace
        $freespace = [math]::Round($freespace / 1MB, 0)

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..'

        # Get list of profiles from computer into listview
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $win32UserProfiles | Add-Member -membertype NoteProperty -name IsLocalAdmin -value $null
        $win32UserProfiles | Add-Member -membertype NoteProperty -name LocalProfileSize -value $null

        $users = $win32UserProfiles | Select-Object -ExpandProperty "SID" | ConvertSID
        $userstrim = $users -creplace '^[^\\]*\\', ''

        $members = net localgroup administrators |
        Where-Object { $_ -AND $_ -notmatch "command completed successfully" } |
        Select-Object -Skip 4

        $i = 0
        ForEach ($user in $userstrim)
        {
            If ($members -contains $user)
            {
                $win32UserProfiles[$i].IsLocalAdmin = $true
                $i++
            }
            Else
            {
                $win32UserProfiles[$i].IsLocalAdmin = $false
                $i++
            }
        }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Getting C:\ & Local Profile Data..'

        #local profile file size check
        $LocalUserProfiles = $win32UserProfiles | Select-Object LocalPath
        $LocalUserProfilesTrim = ForEach ($LocalPath in $LocalUserProfiles) { $LocalPath.LocalPath.substring(9) }

        $i = 0
        $profiles2 = Get-ChildItem C:\Users | Where-Object { Test-Path C:\Users\$_\NTUSER.DAT } | Select-Object -ExpandProperty Name
        foreach ($userprofile in $LocalUserProfilesTrim)
        {
            $largeprofile = Get-ChildItem C:\Users\$userprofile -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum length | Select-Object -ExpandProperty Sum
            $largeprofile = [math]::Round($largeprofile / 1MB, 0)
            $largeprofile = $largeprofile
            $win32UserProfiles[$i].LocalProfileSize = $largeprofile
            $i++
        }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Building Profile Group Box Query..'

        $Profiles = $win32UserProfiles | Select-Object SID, RoamingConfigured, Loaded, IsLocalAdmin, LocalPath, LocalProfileSize, @{Name = "LastLogin"; EXPRESSION = { $_.ConvertToDateTime($_.lastusetime) } }, @{Name = "UserName"; EXPRESSION = { ConvertSID($_.SID) } }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Done!'

#load UI Labels

#SystemInformation
$lbComputerName.Content = $WmiComputerSystem.Name
$lbUSMTStatus.Content = (($InstalledProducts -match 'User State Migration Tool').Count -eq 1)
$lbcfreespace.Content = $freespace

#DomainInformation
$lbDomainName.Content = $DomainName
$lbNetBiosName.Content = $NetBiosName
$lbsecurechannel.Content = $securechannelstatus

#AzureADInformation
$lbAzureAD_Joined.Content = $AzureADStatus
$lbWorkplace_Joined.Content = $Workplace_join
$lbTenantName.Content = $TenantName

Function Test-Button([object]$tbJumpCloudUserName, [object]$tbJumpCloudConnectKey, [object]$tbTempPassword, [object]$lvProfileList)
{
    Write-Debug ('---------------------------------------------------------')
    Write-Debug ('Valid UserName: ' + $tbJumpCloudUserName)
    Write-Debug ('Valid ConnectKey: ' + $tbJumpCloudConnectKey)
    Write-Debug ('Valid Password: ' + $tbTempPassword)
    Write-Debug ('Has UserName not been selected: ' + [System.String]::IsNullOrEmpty($lvProfileList.SelectedItem.UserName))
    If (![System.String]::IsNullOrEmpty($lvProfileList.SelectedItem.UserName))
    {
        If (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpaces $tbJumpCloudUserName.Text) `
                -and (Test-Is40chars $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpaces $tbJumpCloudConnectKey.Text) `
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpaces $tbTempPassword.Text)`
                -and !($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name))
        {
            $script:bDeleteProfile.Content = "Migrate Profile"
            $script:bDeleteProfile.IsEnabled = $true
            Return $true
        }
        Elseif(($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name)){
            $script:bDeleteProfile.Content = "Select Domain Profile"
            $script:bDeleteProfile.IsEnabled = $false
            Return $false
        }
        Else
        {
            $script:bDeleteProfile.Content = "Correct Errors"
            $script:bDeleteProfile.IsEnabled = $false
            Return $false
        }
    }
    Else
    {
        $script:bDeleteProfile.Content = "Select Profile"
        $script:bDeleteProfile.IsEnabled = $false
        Return $false
    }
}

## Form changes & interactions

# EULA checkbox
$script:AcceptEULA = $true
$cb_accepteula.Add_Checked( { $script:AcceptEULA = $true })
$cb_accepteula.Add_Unchecked( { $script:AcceptEULA = $false })

# Install JCAgent checkbox
$script:InstallJCAgent = $true
$cb_installjcagent.Add_Checked( { $script:InstallJCAgent = $true })
$cb_installjcagent.Add_Unchecked( { $script:InstallJCAgent = $false })

# Leave Domain checkbox
$script:LeaveDomain = $false
$cb_leavedomain.Add_Checked( { $script:LeaveDomain = $true })
$cb_leavedomain.Add_Unchecked( { $script:LeaveDomain = $false })

# Force Reboot checkbox
$script:ForceReboot = $false
$cb_forcereboot.Add_Checked( { $script:ForceReboot = $true })
$cb_forcereboot.Add_Unchecked( { $script:ForceReboot = $false })

$tbJumpCloudUserName.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)
        If ((!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpaces $tbJumpCloudUserName.Text)) -eq $false)
        {
            $tbJumpCloudUserName.Background = "#FFC6CBCF"
            $tbJumpCloudUserName.Tooltip = "JumpCloud User Name Can't Be Empty Or Contain Spaces"
        }
        Else
        {
            $tbJumpCloudUserName.Background = "white"
            $tbJumpCloudUserName.Tooltip = $null
            $tbJumpCloudUserName.FontWeight = "Normal"
        }
    })

$tbJumpCloudUserName.add_GotFocus( {
        $tbJumpCloudUserName.Text = ""
    })

$tbJumpCloudConnectKey.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)
        If (((Test-Is40chars $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpaces $tbJumpCloudConnectKey.Text)) -eq $false)
        {
            $tbJumpCloudConnectKey.Background = "#FFC6CBCF"
            $tbJumpCloudConnectKey.Tooltip = "Connect Key Must be 40chars & Not Contain Spaces"
        }
        Else
        {
            $tbJumpCloudConnectKey.Background = "white"
            $tbJumpCloudConnectKey.Tooltip = $null
            $tbJumpCloudConnectKey.FontWeight = "Normal"
        }
    })

$tbJumpCloudConnectKey.add_GotFocus( {
        $tbJumpCloudConnectKey.Text = ""
    })

$tbTempPassword.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)
        If ((!(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpaces $tbTempPassword.Text)) -eq $false)
        {
            $tbTempPassword.Background = "#FFC6CBCF"
            $tbTempPassword.Tooltip = "Connect Key Must Be 40chars & No spaces"
        }
        Else
        {
            $tbTempPassword.Background = "white"
            $tbTempPassword.Tooltip = $null
            $tbTempPassword.FontWeight = "Normal"
        }
    })

# Change button when profile selected
$lvProfileList.Add_SelectionChanged( {
        $script:SelectedUserName = ($lvProfileList.SelectedItem.username)
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)
    })
# AcceptEULA moreinfo link - Mouse button event
$lbMoreInfo.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://github.com/TheJumpCloud/support/tree/BS-ADMU-version_1.0.0/ADMU#EULA--Legal-Explanation') })

$bDeleteProfile.Add_Click( {
        # Build FormResults object
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('AcceptEula') -Value:($AcceptEula)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('InstallJCAgent') -Value:($InstallJCAgent)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('LeaveDomain') -Value:($LeaveDomain)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('ForceReboot') -Value:($ForceReboot)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('DomainUserName') -Value:($SelectedUserName.Substring($SelectedUserName.IndexOf('\') + 1))
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudUserName') -Value:($tbJumpCloudUserName.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('TempPassword') -Value:($tbTempPassword.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudConnectKey') -Value:($tbJumpCloudConnectKey.Text)
        # Close form
        $Form.Close()
    })

# Put the list of profiles in the profile box
$Profiles | ForEach-Object { $lvProfileList.Items.Add($_) | Out-Null }
#===========================================================================
# Shows the form
#===========================================================================
$Form.Showdialog() | Out-Null
If ($bDeleteProfile.IsEnabled -eq $true)
{
    Return $FormResults
}
