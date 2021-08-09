Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Loading ADMU GUI..'

#==============================================================================================
# XAML Code - Imported from Visual Studio WPF Application
#==============================================================================================
[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[xml]$XAML = @'
<Window
     xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
     xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
     Title="JumpCloud ADMU 1.6.7" Height="677.234" Width="1053.775" WindowStartupLocation="CenterScreen" ResizeMode="NoResize" ForceCursor="True">
    <Grid Margin="0,0,-0.2,0.168" RenderTransformOrigin="0.531,0.272">
        <TabControl Name="tc_main" HorizontalAlignment="Left" Height="614" VerticalAlignment="Top" Width="1012">
            <TabItem Name="tab_jcadmu" Header="JumpCloud ADMU">
                <Grid Background="#FFE5E5E5">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="87*"/>
                        <ColumnDefinition Width="919*"/>
                    </Grid.ColumnDefinitions>
                    <GroupBox Header="Migration Steps" HorizontalAlignment="Left" Height="98" Margin="10,0,0,0" VerticalAlignment="Top" Width="993" FontWeight="Bold" Grid.ColumnSpan="2">
                        <TextBlock HorizontalAlignment="Left" TextWrapping="Wrap" VerticalAlignment="Top" Height="70" Width="561" Margin="0,10,0,-5" FontWeight="Normal"><Run Text="1. Select the domain or AzureAD account that you want to migrate to a local account from the list below."/><LineBreak/><Run Text="2. Enter a local account username and password to migrate the selected account to. "/><LineBreak/><Run Text="3. Enter your organizations JumpCloud system connect key."/><LineBreak/><Run Text="4. Click the "/><Run Text="Migrate Profile"/><Run Text=" button."/><LineBreak/><Run/></TextBlock>
                    </GroupBox>
                    <ListView Name="lvProfileList" HorizontalAlignment="Left" Height="226" Margin="10,228,0,0" VerticalAlignment="Top" Width="993" Grid.ColumnSpan="2">
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="System Accounts" DisplayMemberBinding="{Binding UserName}" Width="180"/>
                                <GridViewColumn Header="Last Login" DisplayMemberBinding="{Binding LastLogin}" Width="135"/>
                                <GridViewColumn Header="Currently Active" DisplayMemberBinding="{Binding Loaded}" Width="105" />
                                <GridViewColumn Header="Domain Roaming" DisplayMemberBinding="{Binding RoamingConfigured}" Width="105"/>
                                <GridViewColumn Header="Local Admin" DisplayMemberBinding="{Binding IsLocalAdmin}" Width="105"/>
                                <GridViewColumn Header="Local Path" DisplayMemberBinding="{Binding LocalPath}" Width="140"/>
                                <GridViewColumn Header="Local Profile Size" DisplayMemberBinding="{Binding LocalProfileSize}" Width="105"/>
                            </GridView>
                        </ListView.View>
                    </ListView>
                    <Button Name="bDeleteProfile" Content="Select Profile" HorizontalAlignment="Left" Margin="788,557,0,0" VerticalAlignment="Top" Width="121" Height="23" IsEnabled="False" Grid.Column="1">
                        <Button.Effect>
                            <DropShadowEffect/>
                        </Button.Effect>
                    </Button>
                    <GroupBox Header="System Information" HorizontalAlignment="Left" Height="120" Margin="10,103,0,0" VerticalAlignment="Top" Width="341" FontWeight="Bold" Grid.ColumnSpan="2">
                        <Grid HorizontalAlignment="Left" Height="90" VerticalAlignment="Top" Width="321" Margin="10,0,-2,0">
                            <Label Content="Local Computer Name:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Content="USMT Detected:" HorizontalAlignment="Left" Margin="10,31,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Name="lbComputerName" Content="" HorizontalAlignment="Left" Margin="191,10,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
                            <Label Name="lbUSMTStatus" Content="" HorizontalAlignment="Left" Margin="191,31,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
                            <Label Content="C:\ Free Disk Space:" HorizontalAlignment="Left" Margin="10,57,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Name="lbcfreespace" Content="" HorizontalAlignment="Left" Margin="191,57,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
                        </Grid>
                    </GroupBox>
                    <GroupBox Header="Account Migration Information" HorizontalAlignment="Left" Height="92" Margin="445,459,0,0" VerticalAlignment="Top" Width="471" FontWeight="Bold" Grid.Column="1">
                        <Grid HorizontalAlignment="Left" Height="66.859" Margin="1.212,2.564,0,0" VerticalAlignment="Top" Width="454.842">
                            <Label Content="Local Account Username :" HorizontalAlignment="Left" Margin="7.088,8.287,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Content="Local Account Password :" HorizontalAlignment="Left" Margin="7.088,36.287,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <TextBox Name="tbJumpCloudUserName" HorizontalAlignment="Left" Height="23" Margin="151.11,10.287,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="301.026" Text="Username should match JumpCloud username" Background="#FFC6CBCF" FontWeight="Bold" />
                            <TextBox Name="tbTempPassword" HorizontalAlignment="Left" Height="23" Margin="151.11,39.287,0,0" TextWrapping="Wrap" Text="Temp123!Temp123!" VerticalAlignment="Top" Width="301.026" FontWeight="Normal"/>
                        </Grid>
                    </GroupBox>
                    <GroupBox Header="System Migration Options" HorizontalAlignment="Left" Height="121" Margin="10,459,0,0" VerticalAlignment="Top" Width="517" FontWeight="Bold" Grid.ColumnSpan="2">
                        <Grid HorizontalAlignment="Left" Height="93" Margin="2,0,0,0" VerticalAlignment="Center" Width="505">
                            <Label Name="lbMoreInfo" Content="More Info" HorizontalAlignment="Left" Margin="91.649,38,0,-0.876" VerticalAlignment="Top" Width="65.381" FontSize="11" FontWeight="Bold" FontStyle="Italic" Foreground="#FF005DFF"/>
                            <CheckBox Name="cb_accepteula" Content="Accept EULA" HorizontalAlignment="Left" Margin="3.649,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="True"/>
                            <Label Content="JumpCloud Connect Key :" HorizontalAlignment="Left" Margin="3.649,7.999,0,0" VerticalAlignment="Top" AutomationProperties.HelpText="https://console.jumpcloud.com/#/systems/new" ToolTip="https://console.jumpcloud.com/#/systems/new" FontWeight="Normal"/>
                            <TextBox Name="tbJumpCloudConnectKey" HorizontalAlignment="Left" Height="23" Margin="148.673,10,0,0" TextWrapping="Wrap" Text="Enter JumpCloud Connect Key" VerticalAlignment="Top" Width="301.026" Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False"/>
                            <CheckBox Name="cb_installjcagent" Content="Install JCAgent" HorizontalAlignment="Left" Margin="155.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                            <CheckBox Name="cb_leavedomain" Content="Leave Domain" HorizontalAlignment="Left" Margin="258.699,44.326,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                            <CheckBox Name="cb_forcereboot" Content="Force Reboot" HorizontalAlignment="Left" Margin="391,68,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                            <CheckBox Name="cb_custom_xml" Content="Use USMT Custom.XML" HorizontalAlignment="Left" Margin="4,68,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <CheckBox Name="cb_convertprofile" Content="Convert Profile" HorizontalAlignment="Left" Margin="156,68,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="true"/>
                            <CheckBox Name="cb_createrestore" Content="Create Restore Point" HorizontalAlignment="Left" Margin="258,68,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                            <CheckBox Name="cb_updatehomepath" Content="Update Home Path" HorizontalAlignment="Left" Margin="359,44,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                        </Grid>
                    </GroupBox>
                    <GroupBox Header="Domain Information" HorizontalAlignment="Left" Height="120" Margin="269,103,0,0" VerticalAlignment="Top" Width="321" FontWeight="Bold" Grid.Column="1">
                        <Grid HorizontalAlignment="Left" Height="95" Margin="10,0,0,0" VerticalAlignment="Top" Width="297">
                            <Label Content="Domain Name:" HorizontalAlignment="Left" Margin="10,10,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Name="lbDomainName" Content="" Margin="167,11,10,59" Foreground="Black" FontWeight="Normal"/>
                            <Label Content="Secure Channel Healthy:" HorizontalAlignment="Left" Margin="10,62,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Name="lbsecurechannel" Content="" HorizontalAlignment="Left" Margin="167,62,0,0" VerticalAlignment="Top" Width="120" FontWeight="Normal"/>
                            <Label Content="NetBios Name:" HorizontalAlignment="Left" Margin="10,36,0,0" VerticalAlignment="Top" FontWeight="Normal"/>
                            <Label Name="lbNetBios" Content="" Margin="167,36,10,33" Foreground="Black" FontWeight="Normal"/>
                        </Grid>
                    </GroupBox>
                    <GroupBox Header="AzureAD Information" HorizontalAlignment="Left" Height="120" Margin="595,103,0,0" VerticalAlignment="Top" Width="321" FontWeight="Bold" Grid.Column="1">
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
            </TabItem>
            <TabItem Name="tab_usmtcustomxml" Header="USMT Custom.XML" IsEnabled="False">
                <Grid Background="#FFE5E5E5">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="89*"/>
                        <ColumnDefinition Width="917*"/>
                    </Grid.ColumnDefinitions>
                    <TextBox Name="tb_customxml" HorizontalAlignment="Left" Height="370" Margin="10,103,0,0" AcceptsReturn="True" VerticalScrollBarVisibility="Visible" TextWrapping="WrapWithOverflow" VerticalAlignment="Top" Width="986" Text="test" Grid.ColumnSpan="2" />
                    <TextBox Name="tb_xmlerror" HorizontalAlignment="Left" Height="74" Margin="10,478,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="986" Grid.ColumnSpan="2" BorderBrush="Black" IsEnabled="False"/>
                    <Label Name="lbMoreInfo_xml" Content="More Info On Customizing USMT XML" HorizontalAlignment="Left" Margin="358,48,0,0" VerticalAlignment="Top" Width="206" FontSize="11" FontWeight="Bold" FontStyle="Italic" Foreground="#FF005DFF" Grid.Column="1"/>
                    <GroupBox Header="USMT Custom.XML" HorizontalAlignment="Left" Height="98" Margin="10,0,0,0" VerticalAlignment="Top" Width="412" FontWeight="Bold" Grid.ColumnSpan="2">
                        <TextBlock HorizontalAlignment="Left" TextWrapping="Wrap" VerticalAlignment="Top" Height="70" Width="429" Margin="0,10,0,-5" FontWeight="Normal"><Run Text="1. Modify XML to include and exclude as required."/><LineBreak/><Run Text="2. Click 'Verify XML' button to validate the xml. "/><LineBreak/><Run Text="3. If not valid, view errors below and correct, then verify again."/><LineBreak/><Run Text="4. Click OK to return to Jumpcloud ADMU and use valid XML."/><Run/></TextBlock>
                    </GroupBox>
                    <Button Name="btn_custom_ok" Content="OK" HorizontalAlignment="Left" Margin="654,559,0,0" VerticalAlignment="Top" Width="121" Height="23" IsEnabled="False" Grid.Column="1">
                        <Button.Effect>
                            <DropShadowEffect/>
                        </Button.Effect>
                    </Button>
                    <Button Name="btn_custom_cancel" Content="CANCEL" HorizontalAlignment="Left" Margin="786,559,0,0" VerticalAlignment="Top" Width="121" Height="23" IsEnabled="True" Grid.Column="1">
                        <Button.Effect>
                            <DropShadowEffect/>
                        </Button.Effect>
                    </Button>
                </Grid>
            </TabItem>
        </TabControl>
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

        #USMT Path
        $UserStateMigrationToolx64Path = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\User State Migration Tool\'
        $UserStateMigrationToolx86Path = 'C:\Program Files\Windows Kits\10\Assessment and Deployment Kit\User State Migration Tool\'

        Switch ([System.IntPtr]::Size)
        {
        8 { $UserStateMigrationToolx64Path }
        4 { $UserStateMigrationToolx86Path }
        Default { Write-ToLog -Message:('Unknown OSArchitecture') -Level:('Error') }
        }

        $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
        Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Checking AzureAD Status..'
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

        Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Getting Installed Applications..'

        $InstalledProducts = (Get-WmiObject -Class:('Win32_Product') | Select-Object Name)
        $Disk = Get-WmiObject -Class Win32_logicaldisk -Filter "DeviceID = 'C:'"
        $freespace = $Disk.FreeSpace
        $freespace = [math]::Round($freespace / 1MB, 0)

        Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..'

        #region custom xml
$usmtcustom = [xml] @"
<migration urlid="http://www.microsoft.com/migration/1.0/migxmlext/AppDataMig">
	<component context="User" type="Application">
        <displayName>Local AppData</displayName>
        <paths>
            <path type="File">%CSIDL_LOCAL_APPDATA%</path>
        </paths>
        <role role="Settings">
            <rules>
                <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                    <objectSet>
                        <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                    </objectSet>
                </include>
                <merge script="MigXmlHelper.DestinationPriority()">
                    <objectSet>
                        <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                    </objectSet>
                </merge>
            </rules>
        </role>
    </component>
	<component context="User" type="Application">
        <displayName>Roaming AppData</displayName>
        <paths>
            <path type="File">%CSIDL_LOCAL_APPDATA%</path>
        </paths>
        <role role="Settings">
            <rules>
                <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                    <objectSet>
                        <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                    </objectSet>
                </include>
                <merge script="MigXmlHelper.DestinationPriority()">
                    <objectSet>
                        <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
						<pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                    </objectSet>
                </merge>
            </rules>
        </role>
    </component>

	</migration>
"@
        #endregion custom xml

        # Load custom xml
        [string[]]$text = $usmtcustom.OuterXml #or use Get-Content to read an XML File
        $data = New-Object System.Collections.ArrayList
        [void] $data.Add($text -join "`n")
        $tmpDoc = New-Object System.Xml.XmlDataDocument
        $tmpDoc.LoadXml($data -join "`n")
        $sw = New-Object System.IO.StringWriter
        $writer = New-Object System.Xml.XmlTextWriter($sw)
        $writer.Formatting = [System.Xml.Formatting]::Indented
        $tmpDoc.WriteContentTo($writer)
        $tb_customxml.Text = $sw.ToString()

        Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Getting C:\ & Local Profile Data..'
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
                    Name              = Convert-Sid $listItem.PSChildName
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

        Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Building Profile Group Box Query..'

        $Profiles = $users | Select-Object SID, RoamingConfigured, Loaded, IsLocalAdmin, LocalPath, LocalProfileSize, LastLogin, @{Name = "UserName"; EXPRESSION = { $_.Name } }

        Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Done!'

#load UI Labels

#SystemInformation
$lbComputerName.Content = $WmiComputerSystem.Name
$lbUSMTStatus.Content = (($InstalledProducts -match 'User State Migration Tool').Count -eq 1)
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
        If (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) `
                -and (Test-Is40chars $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text) -and ($cb_installjcagent.IsChecked -eq $true)`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text))
        {
            $script:bDeleteProfile.Content = "Migrate Profile"
            $script:bDeleteProfile.IsEnabled = $true
            Return $true
        }
        Elseif(!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) `
        -and ($cb_installjcagent.IsChecked -eq $false)`
        -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
        -and !($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name)`
        -and !(Test-Localusername $tbJumpCloudUserName.Text))
        {
            $script:bDeleteProfile.Content = "Migrate Profile"
            $script:bDeleteProfile.IsEnabled = $true
            Return $true
        }
        Elseif ($lvProfileList.selectedItem.Username -eq 'UNKNOWN ACCOUNT')
        {
            # Unmatched Profile, prevent migration
            $script:bDeleteProfile.Content = "Select Domain Profile"
            $script:bDeleteProfile.IsEnabled = $false
            Return $false
        }
        Elseif (($($lvProfileList.selectedItem.Username) -split '\\').count -ge 2 )
        {
            # Test if profile is in domain\username format
            if (($($lvProfileList.selectedItem.Username) -split '\\')[0] -match $WmiComputerSystem.Name)
            {
                # if the profile domain name matches system name, prevent migration
                $script:bDeleteProfile.Content = "Select Domain Profile"
                $script:bDeleteProfile.IsEnabled = $false
                Return $false
            }
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
$cb_accepteula.Add_Checked({$script:AcceptEULA = $true})
$cb_accepteula.Add_Unchecked({$script:AcceptEULA = $false})

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
# Checked And Not Running As System And Joined To Azure AD
$cb_leavedomain.Add_Checked({
if (([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).user.Value -match "S-1-5-18")) -eq $false -and !($AzureADStatus -eq 'NO' ))
{
# Throw Popup, OK Loads URL, Cancel Closes. Disables And Unchecks LeaveDomain Checkbox Else LeaveDomain -eq $true
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
$result = [System.Windows.Forms.MessageBox]::Show("To leave AzureAD, ADMU must be run as NTAuthority\SYSTEM.`nFor more information on the requirements`nSelect 'OK' else select 'Cancel'" , "JumpCloud ADMU" , 1)
if ($result -eq 'OK') {
    [Diagnostics.Process]::Start('https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Leaving-AzureAD-Domains')
}
Write-ToLog -Message:('Unable to leave AzureAD, ADMU Script must be run as NTAuthority\SYSTEM.This will have to be completed manually. For more information on the requirements read https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Leaving-AzureAD-Domains') -Level:('Error')
$script:LeaveDomain = $false
$cb_leavedomain.IsChecked = $false
$cb_leavedomain.IsEnabled = $false
}
$script:LeaveDomain = $true
})
$cb_leavedomain.Add_Unchecked({$script:LeaveDomain = $false})

# Force Reboot checkbox
$script:ForceReboot = $false
$cb_forcereboot.Add_Checked({$script:ForceReboot = $true})
$cb_forcereboot.Add_Unchecked({$script:ForceReboot = $false})

# Convert Profile checkbox
$script:ConvertProfile = $true
$cb_convertprofile.Add_Checked({$script:ConvertProfile = $true})
$cb_convertprofile.Add_Checked({$cb_custom_xml.IsEnabled = $false})
$cb_convertprofile.Add_Checked({$cb_accepteula.IsEnabled = $false})
$cb_convertprofile.Add_Unchecked({$script:ConvertProfile = $false})
$cb_convertprofile.Add_UnChecked({$cb_custom_xml.IsEnabled = $True})
$cb_convertprofile.Add_UnChecked({$cb_accepteula.IsEnabled = $True})
$cb_custom_xml.Add_UnChecked({$tab_usmtcustomxml.IsEnabled = $false})

# Create Restore Point checkbox
$script:CreateRestore = $false
$cb_createrestore.Add_Checked({$script:CreateRestore = $true})
$cb_createrestore.Add_Unchecked({$script:CreateRestore = $false})

# Update Home Path checkbox
$script:UpdateHomePath = $false
$cb_updatehomepath.Add_Checked({$script:UpdateHomePath = $true})
$cb_updatehomepath.Add_Unchecked({$script:UpdateHomePath = $false})

# Custom XML checkbox
$script:Customxml = $false
$cb_custom_xml.Add_Checked({$script:Customxml = $true})
$cb_custom_xml.Add_Checked({$tab_usmtcustomxml.IsEnabled = $true})
$cb_custom_xml.Add_Checked({$tab_usmtcustomxml.IsSelected = $true})
$cb_custom_xml.Add_Unchecked({$script:Customxml = $false})
$cb_custom_xml.Add_UnChecked({$tab_usmtcustomxml.IsEnabled = $false})

$tbJumpCloudUserName.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList)
        If ((Test-IsNotEmpty $tbJumpCloudUserName.Text) -or (!(Test-HasNoSpace $tbJumpCloudUserName.Text)) -or (Test-Localusername $tbJumpCloudUserName.Text))
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
        If (((Test-Is40chars $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text)) -eq $false)
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
        If ((!(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)) -eq $false)
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
$lbMoreInfo.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/eula-legal-explanation') })
# Custom USMT XML moreinfo link - Mouse button event
$lbMoreInfo_xml.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://docs.microsoft.com/en-us/windows/deployment/usmt/usmt-customize-xml-files') })

$bDeleteProfile.Add_Click( {
        # Build FormResults object
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('AcceptEula') -Value:($AcceptEula)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('InstallJCAgent') -Value:($InstallJCAgent)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('LeaveDomain') -Value:($LeaveDomain)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('ForceReboot') -Value:($ForceReboot)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('ConvertProfile') -Value:($ConvertProfile)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('CreateRestore') -Value:($CreateRestore)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('UpdateHomePath') -Value:($UpdateHomePath)
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
$tb_customxml.add_TextChanged({
    [string[]]$text = $tb_customxml.Text #or use Get-Content to read an XML File
    $data = New-Object System.Collections.ArrayList
    [void] $data.Add($text -join "`n")
    $tmpDoc = New-Object System.Xml.XmlDataDocument
    $tmpDoc.LoadXml($data -join "`n")
    $data | Out-File ('C:\Windows\Temp\custom.xml')
    $verifiedxml = (Test-XMLFile -xmlFilePath ('C:\Windows\Temp\custom.xml'))
    $tab_jcadmu.IsEnabled = $false

    if ($verifiedxml -eq $true) {
    $tb_xmlerror.Text = 'Valid XML'
    $tb_xmlerror.BorderBrush="Black"
    $btn_custom_ok.IsEnabled = $true
    }
    elseif ($verifiedxml -eq $false) {
    $tb_xmlerror.Text = $Error[0]
    $tb_xmlerror.BorderBrush="Red"
    $btn_custom_ok.IsEnabled = $false
    }
})

$tab_usmtcustomxml.add_GotFocus({
    [string[]]$text = $tb_customxml.Text #or use Get-Content to read an XML File
    $data = New-Object System.Collections.ArrayList
    [void] $data.Add($text -join "`n")
    $tmpDoc = New-Object System.Xml.XmlDataDocument
    $tmpDoc.LoadXml($data -join "`n")
    $data | Out-File ('C:\Windows\Temp\custom.xml')
    $verifiedxml = (Test-XMLFile -xmlFilePath ('C:\Windows\Temp\custom.xml'))
    $tab_jcadmu.IsEnabled = $false

    if ($verifiedxml -eq $true) {
    $tb_xmlerror.Text = 'Valid XML'
    $tb_xmlerror.BorderBrush="Black"
    $btn_custom_ok.IsEnabled = $true
    }
    elseif ($verifiedxml -eq $false) {
    $tb_xmlerror.Text = $Error[0]
    $tb_xmlerror.BorderBrush="Red"
    $btn_custom_ok.IsEnabled = $false
    }
})

$btn_custom_ok.Add_Click({$tab_jcadmu.IsSelected = $true})
$btn_custom_cancel.Add_Click({
    $cb_custom_xml.IsChecked = $false
    $tab_jcadmu.IsSelected = $true
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
