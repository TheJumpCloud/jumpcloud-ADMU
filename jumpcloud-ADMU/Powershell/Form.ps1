Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Loading ADMU GUI..'

#==============================================================================================
# XAML Code - Imported from Visual Studio WPF Application
#==============================================================================================
[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[xml]$XAML = @'
<Window
     xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
     xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
     Title="JumpCloud ADMU 2.0.0" Height="669" Width="1053.775" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" ForceCursor="True">
    <Grid Margin="0,0,0,31" RenderTransformOrigin="0.531,0.272">
        <TabControl Name="tc_main" HorizontalAlignment="Left" Height="614" VerticalAlignment="Top" Width="1012"/>
        <GroupBox Header="Migration Steps" HorizontalAlignment="Left" Height="98" Margin="10,0,0,0" VerticalAlignment="Top" Width="993" FontWeight="Bold">
            <TextBlock HorizontalAlignment="Left" TextWrapping="Wrap" VerticalAlignment="Top" Height="70" Width="561" Margin="0,10,0,-5" FontWeight="Normal"><Run Text="1. Select the domain or AzureAD account that you want to migrate to a local account from the list below."/><LineBreak/><Run Text="2. Enter a local account username and password to migrate the selected account to. "/><LineBreak/><Run Text="3. Enter your organizations JumpCloud system connect key."/><LineBreak/><Run Text="4. Click the "/><Run Text="Migrate Profile"/><Run Text=" button."/><LineBreak/><Run/></TextBlock>
        </GroupBox>
        <ListView Name="lvProfileList" HorizontalAlignment="Left" Height="226" Margin="10,228,0,0" VerticalAlignment="Top" Width="993">
            <ListView.View>
                <GridView>
                    <GridViewColumn Header="System Accounts" DisplayMemberBinding="{Binding UserName}" Width="287"/>
                    <GridViewColumn Header="Last Login" DisplayMemberBinding="{Binding LastLogin}" Width="135"/>
                    <GridViewColumn Header="Currently Active" DisplayMemberBinding="{Binding Loaded}" Width="105" />
                    <GridViewColumn Header="Domain Roaming" DisplayMemberBinding="{Binding RoamingConfigured}" Width="105"/>
                    <GridViewColumn Header="Local Admin" DisplayMemberBinding="{Binding IsLocalAdmin}" Width="105"/>
                    <GridViewColumn Header="Local Path" DisplayMemberBinding="{Binding LocalPath}" Width="140"/>
                    <GridViewColumn Header="Local Profile Size" DisplayMemberBinding="{Binding LocalProfileSize}" Width="105"/>
                </GridView>
            </ListView.View>
        </ListView>
        <Button Name="bDeleteProfile" Content="Select Profile" HorizontalAlignment="Left" Margin="875,557,0,0" VerticalAlignment="Top" Width="121" Height="23" IsEnabled="False">
            <Button.Effect>
                <DropShadowEffect/>
            </Button.Effect>
        </Button>
        <GroupBox Header="System Information" HorizontalAlignment="Left" Height="120" Margin="10,103,0,0" VerticalAlignment="Top" Width="341" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="90" VerticalAlignment="Top" Width="321" Margin="10,0,-2,0">
                <Label Content="Local Computer Name:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbComputerName" Content="" HorizontalAlignment="Left" Margin="191,10,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
                <Label Content="C:\ Free Disk Space:" HorizontalAlignment="Left" Margin="10,57,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbcfreespace" Content="" HorizontalAlignment="Left" Margin="191,57,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="Account Migration Information" HorizontalAlignment="Left" Height="92" Margin="532,459,0,0" VerticalAlignment="Top" Width="471" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="66.859" Margin="1.212,2.564,0,0" VerticalAlignment="Top" Width="454.842">
                <Label Content="Local Account Username :" HorizontalAlignment="Left" Margin="7.088,8.287,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Content="Local Account Password :" HorizontalAlignment="Left" Margin="7.088,36.287,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <TextBox Name="tbJumpCloudUserName" HorizontalAlignment="Left" Height="23" Margin="151.11,10.287,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="301.026" Text="Username should match JumpCloud username" Background="#FFC6CBCF" FontWeight="Bold" />
                <TextBox Name="tbTempPassword" HorizontalAlignment="Left" Height="23" Margin="151.11,39.287,0,0" TextWrapping="Wrap" Text="Temp123!Temp123!" VerticalAlignment="Top" Width="301.026" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="System Migration Options" HorizontalAlignment="Left" Height="121" Margin="10,459,0,0" VerticalAlignment="Top" Width="517" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="93" Margin="2,3,0,0" VerticalAlignment="Top" Width="456">
                <Label Content="JumpCloud Connect Key :" HorizontalAlignment="Left" Margin="3.649,7.999,0,0" VerticalAlignment="Top" AutomationProperties.HelpText="https://console.jumpcloud.com/#/systems/new" ToolTip="https://console.jumpcloud.com/#/systems/new" FontWeight="Normal"/>
                <TextBox Name="tbJumpCloudConnectKey" HorizontalAlignment="Left" Height="23" Margin="148.673,10,0,0" TextWrapping="Wrap" Text="Enter JumpCloud Connect Key" VerticalAlignment="Top" Width="301.026" Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False"/>
                <CheckBox Name="cb_installjcagent" Content="Install JCAgent" HorizontalAlignment="Left" Margin="155.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_leavedomain" Content="Leave Domain" HorizontalAlignment="Left" Margin="258.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_forcereboot" Content="Force Reboot" HorizontalAlignment="Left" Margin="359.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_createrestore" Content="Create Restore Point" HorizontalAlignment="Left" Margin="258,68,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="Domain Information" HorizontalAlignment="Left" Height="120" Margin="356,103,0,0" VerticalAlignment="Top" Width="321" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="95" Margin="10,0,0,0" VerticalAlignment="Top" Width="297">
                <Label Content="Domain Name:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbDomainName" Content="" Margin="167,11,10,59" Foreground="Black" FontWeight="Normal"/>
                <Label Content="Secure Channel Healthy:" HorizontalAlignment="Left" Margin="10,62,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbsecurechannel" Content="" HorizontalAlignment="Left" Margin="167,62,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
                <Label Content="NetBios Name:" HorizontalAlignment="Left" Margin="10,36,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbNetBios" Content="" Margin="167,36,10,33" Foreground="Black" FontWeight="Normal"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="AzureAD Information" HorizontalAlignment="Left" Height="120" Margin="682,103,0,0" VerticalAlignment="Top" Width="321" FontWeight="Bold">
            <Grid HorizontalAlignment="Left" Height="90" Margin="10,0,0,0" VerticalAlignment="Top" Width="297">
                <Label Content="AzureAD Joined:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbAzureAD_Joined" Content="" Margin="168,10,10,54" Foreground="Black" FontWeight="Normal"/>
                <Label Content="Workplace Joined:" HorizontalAlignment="Left" Margin="10,36,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbWorkplace_Joined" Content="" Margin="169,36,10,28" Foreground="Black" FontWeight="Normal"/>
                <Label Content="Tenant Name:" HorizontalAlignment="Left" Margin="10,62,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                <Label Name="lbTenantName" Content="" Margin="168,62,10,2" Foreground="Black" FontWeight="Normal"/>
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
        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Checking AzureAD Status..'
        if ($WmiComputerSystem.PartOfDomain) {
            $WmiComputerDomain = Get-WmiObject -Class:('Win32_ntDomain')
            $securechannelstatus = Test-ComputerSecureChannel

            $nbtstat = nbtstat -n
            foreach ($line in $nbtStat)
            {
                if ($line -match '^\s*([^<\s]+)\s*<00>\s*GROUP')
                {
                    $NetBiosName = $matches[1]
                }
            }

            if([System.String]::IsNullOrEmpty($WmiComputerDomain[0].DnsForestName) -and $securechannelstatus -eq $false)
            {
                $DomainName = 'Fix Secure Channel'
            } else {
                $DomainName = [string]$WmiComputerDomain.DnsForestName
            }
                $NetBiosName = [string]$NetBiosName
        }
        elseif ($WmiComputerSystem.PartOfDomain -eq $false) {
            $DomainName = 'N/A'
            $NetBiosName = 'N/A'
            $securechannelstatus = 'N/A'
        }
        if ((Get-CimInstance Win32_OperatingSystem).Version -match '10') {
            $AzureADInfo = dsregcmd.exe /status
            foreach ($line in $AzureADInfo) {
                if ($line -match "AzureADJoined : ") {
                    $AzureADStatus = ($line.trimstart('AzureADJoined : '))
                }
                if ($line -match "WorkplaceJoined : ") {
                    $Workplace_join = ($line.trimstart('WorkplaceJoined : '))
                }
                if ($line -match "TenantName : ") {
                    $TenantName = ($line.trimstart('TenantName : '))
                }
            }
        }
        else {
            $AzureADStatus = 'N/A'
            $Workplace_join = 'N/A'
            $TenantName = 'N/A'
        }

        $FormResults = [PSCustomObject]@{ }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..'
        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Getting C:\ & Local Profile Data..'
        # Get Valid SIDs from the Registry and build user object
        $registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $profileList = @()
        foreach ($profile in $registyProfiles) {
            $profileList += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath
        }
        # List to store users
        $users = @()
        foreach ($listItem in $profileList) {
            $sidPattern = "^S-\d-\d+-(\d+-){1,14}\d+$"
            $isValidFormat = [regex]::IsMatch($($listItem.PSChildName), $sidPattern);
            # Get Valid SIDs
            if ($isValidFormat) {
                # Populate Users List
                $users += [PSCustomObject]@{
                    Name              = ConvertSID $listItem.PSChildName
                    LocalPath         = $listItem.ProfileImagePath
                    SID               = $listItem.PSChildName
                    IsLocalAdmin      = $null
                    LocalProfileSize  = $null
                    Loaded            = $null
                    RoamingConfigured = $null
                    LastLogin         = $null
                }
            }
        }
        # Get Win32 Profiles to merge data with valid SIDs
        $win32UserProfiles = Get-WmiObject -Class:('Win32_UserProfile') -Property * | Where-Object { $_.Special -eq $false }
        $date_format = "yyyy-MM-dd HH:mm"
        foreach ($user in $users) {
            # Get Data from Win32Profile
            foreach ($win32user in $win32UserProfiles) {
                if ($($user.SID) -eq $($win32user.SID)) {
                    $user.RoamingConfigured = $win32user.RoamingConfigured
                    $user.Loaded = $win32user.Loaded
                    if ([string]::IsNullOrEmpty($($win32user.LastUseTime))){
                        $user.LastLogin = "N/A"
                    }
                    else{
                        $user.LastLogin = [System.Management.ManagementDateTimeConverter]::ToDateTime($($win32user.LastUseTime)).ToUniversalTime().ToSTring($date_format)
                    }
                }
            }
            # Get Admin Status
            try {
                $admin = Get-LocalGroupMember -Member "$($user.SID)" -Name "Administrators" -EA SilentlyContinue
            }
            catch {
                $user = Get-LocalGroupMember -Member "$($user.SID)" -Name "Users"
            }
            if ($admin) {
                $user.IsLocalAdmin = $true
            }
            else {
                $user.IsLocalAdmin = $false
            }
            # Get Profile Size
            $largeprofile = Get-ChildItem $($user.LocalPath) -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum length | Select-Object -ExpandProperty Sum
            $largeprofile = [math]::Round($largeprofile / 1MB, 0)
            $user.LocalProfileSize = $largeprofile
        }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Building Profile Group Box Query..'

        $Profiles = $users | Select-Object SID, RoamingConfigured, Loaded, IsLocalAdmin, LocalPath, LocalProfileSize, LastLogin, @{Name = "UserName"; EXPRESSION = { $_.Name } }

        Write-Log 'Loading Jumpcloud ADMU. Please Wait.. Done!'

#load UI Labels

#SystemInformation
$lbComputerName.Content = $WmiComputerSystem.Name
$lbcfreespace.Content = $freespace

#DomainInformation
$lbDomainName.Content = $DomainName
$lbNetBios.Content = $NetBiosName
$lbsecurechannel.Content = $securechannelstatus

#AzureADInformation
$lbAzureAD_Joined.Content = $AzureADStatus
$lbWorkplace_Joined.Content = $Workplace_join
$lbTenantName.Content = $TenantName

Function Test-Button([object]$tbJumpCloudUserName, [object]$tbJumpCloudConnectKey, [object]$tbTempPassword, [object]$lvProfileList)
{
    If (![System.String]::IsNullOrEmpty($lvProfileList.SelectedItem.UserName))
    {
        If (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpaces $tbJumpCloudUserName.Text) `
                -and (Test-Is40chars $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpaces $tbJumpCloudConnectKey.Text) -and ($cb_installjcagent.IsChecked -eq $true)`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpaces $tbTempPassword.Text)`
                -and !($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text))
        {
            $script:bDeleteProfile.Content = "Migrate Profile"
            $script:bDeleteProfile.IsEnabled = $true
            Return $true
        }
        Elseif(!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpaces $tbJumpCloudUserName.Text) `
        -and ($cb_installjcagent.IsChecked -eq $false)`
        -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpaces $tbTempPassword.Text)`
        -and !($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name)`
        -and !(Test-Localusername $tbJumpCloudUserName.Text))
        {
            $script:bDeleteProfile.Content = "Migrate Profile"
            $script:bDeleteProfile.IsEnabled = $true
            Return $true
        }
        Elseif(($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name) -or ($lvProfileList.selectedItem.Username -eq 'UNKNOWN ACCOUNT')){
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

# Install JCAgent checkbox
$script:InstallJCAgent = $false
$cb_installjcagent.Add_Checked({Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)})
$cb_installjcagent.Add_Checked({$script:InstallJCAgent = $true})
$cb_installjcagent.Add_Checked({$tbJumpCloudConnectKey.IsEnabled =$true})
$cb_installjcagent.Add_UnChecked({Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)})
$cb_installjcagent.Add_Unchecked({$script:InstallJCAgent = $false})
$cb_installjcagent.Add_Unchecked({$tbJumpCloudConnectKey.IsEnabled =$false})

# Leave Domain checkbox
$script:LeaveDomain = $false
$cb_leavedomain.Add_Checked({$script:LeaveDomain = $true})
$cb_leavedomain.Add_Unchecked({$script:LeaveDomain = $false})

# Force Reboot checkbox
$script:ForceReboot = $false
$cb_forcereboot.Add_Checked({$script:ForceReboot = $true})
$cb_forcereboot.Add_Unchecked({$script:ForceReboot = $false})

# Create Restore Point checkbox
$script:CreateRestore = $false
$cb_createrestore.Add_Checked({$script:CreateRestore = $true})
$cb_createrestore.Add_Unchecked({$script:CreateRestore = $false})

$tbJumpCloudUserName.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)
        If ((Test-IsNotEmpty $tbJumpCloudUserName.Text) -or (!(Test-HasNoSpaces $tbJumpCloudUserName.Text)) -or (Test-Localusername $tbJumpCloudUserName.Text))
        {
            $tbJumpCloudUserName.Background = "#FFC6CBCF"
            $tbJumpCloudUserName.Tooltip = "Local account user name can not be empty, contain spaces or already exist on the local system."
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

$bDeleteProfile.Add_Click( {
        # Build FormResults object
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('AcceptEula') -Value:($AcceptEula)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('InstallJCAgent') -Value:($InstallJCAgent)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('LeaveDomain') -Value:($LeaveDomain)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('ForceReboot') -Value:($ForceReboot)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('ConvertProfile') -Value:($ConvertProfile)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('CreateRestore') -Value:($CreateRestore)
        # Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('DomainUserName') -Value:($SelectedUserName.Substring($SelectedUserName.IndexOf('\') + 1))
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('DomainUserName') -Value:($SelectedUserName)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudUserName') -Value:($tbJumpCloudUserName.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('TempPassword') -Value:($tbTempPassword.Text)
        if(($tbJumpCloudConnectKey.Text).length -eq 40){
            Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudConnectKey') -Value:($tbJumpCloudConnectKey.Text)
        }
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('NetBiosName') -Value:($SelectedUserName)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('Customxml') -Value:($Customxml)
        # Close form
        $Form.Close()
    })

# Put the list of profiles in the profile box
$Profiles | ForEach-Object { $lvProfileList.Items.Add($_) | Out-Null }
#===========================================================================
# Shows the form
#===========================================================================
$Form.Showdialog()
If ($bDeleteProfile.IsEnabled -eq $true)
{
    Return $FormResults
}