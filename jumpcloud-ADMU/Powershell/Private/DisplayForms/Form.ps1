Function Show-SelectionForm {

    # Set source here. Take note in the XAML as to where the variable name was taken.

    #==============================================================================================
    # XAML Code - Imported from Visual Studio WPF Application
    #==============================================================================================
    $types = @(
        'PresentationFramework',
        'PresentationCore',
        'System.Windows.Forms',
        'System.Drawing',
        'WindowsBase'
    )
    foreach ($type in $types) {
        if (-not ([System.Management.Automation.PSTypeName]$type).Type) {
            [void][System.Reflection.Assembly]::LoadWithPartialName($type)
            Add-Type -AssemblyName $type
        }
    }
    # [void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
    # [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    # [void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    # # Add-Type -AssemblyName System.Windows.Forms
    # Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing
    [xml]$XAML = @'
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="JumpCloud ADMU 2.7.11"
        WindowStyle="SingleBorderWindow"
        ResizeMode="NoResize"
        Background="White" ScrollViewer.VerticalScrollBarVisibility="Visible" ScrollViewer.HorizontalScrollBarVisibility="Visible" Width="1020" Height="590">
    <Window.Resources>
        <Style TargetType="PasswordBox">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="PasswordBox">
                        <Border
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="1"
                                CornerRadius="1.5">
                            <ScrollViewer x:Name="PART_ContentHost" />
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="RoundedTextBoxStyle" TargetType="TextBox">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border Background="{TemplateBinding Background}"
                            BorderBrush="{TemplateBinding BorderBrush}"
                            BorderThickness="{TemplateBinding BorderThickness}"
                            CornerRadius="1.5">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="2,2,0,0" HorizontalAlignment="Left" VerticalAlignment="Top"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="NoHeaderGroupBoxStyle" TargetType="{x:Type GroupBox}">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type GroupBox}">
                        <Border BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="4">
                            <Grid>
                                <ContentPresenter ContentSource="Header" RecognizesAccessKey="True" Margin="0" Visibility="Collapsed"/>
                                <ContentPresenter Margin="3" />
                            </Grid>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="TextBlock">
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="LineHeight" Value="21"/>
            <Setter Property="Foreground" Value="#202D38"/>
        </Style>
        <Style TargetType="Label">
            <Setter Property="FontFamily" Value="Segoe UI"/>
        </Style>
        <Style TargetType="CheckBox">
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="Foreground" Value="#202D38"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Foreground" Value="#202D38"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Background" Value="#41C8C3"/>
        </Style>
    </Window.Resources>
    <Grid
        Name="grid1"
        Focusable="True">
        <Grid Margin="10,0,10,0">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto" MinWidth="479"/>
                <ColumnDefinition Width="500"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="270"/>
                <RowDefinition Height="Auto"/>

            </Grid.RowDefinitions>
            <Image Name="JCLogoImg" Source="..." Height="23" VerticalAlignment="Top" Margin="0,10,258,0" Width="auto" HorizontalAlignment="Left"/>

            <!-- System Information -->
            <GroupBox Header="" Style="{StaticResource NoHeaderGroupBoxStyle}" Height="186" Margin="0,47,0,0" HorizontalAlignment="Left" VerticalAlignment="Top" Width="295" Grid.Row="0" Grid.Column="0">
                <Grid HorizontalAlignment="Center" VerticalAlignment="Top" Width="270" MinWidth="245" Margin="0,0,0,0">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="160"/>
                    </Grid.RowDefinitions>
                    <Label Content="System Information" Foreground="#202D38" HorizontalAlignment="Left" VerticalAlignment="Top" FontWeight="SemiBold" Margin="0,5,0,0" Grid.RowSpan="2" Height="26"/>
                    <Grid Grid.Row="1" Margin="0,36,0,0">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="125"/>
                            <ColumnDefinition Width="125"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="25"/>
                            <RowDefinition Height="25"/>
                            <RowDefinition Height="25"/>
                            <RowDefinition Height="25"/>
                            <RowDefinition Height="25"/>
                        </Grid.RowDefinitions>
                        <Label Content="Computer Name:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="0" />
                        <Label Content="Domain Name:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="1" />
                        <Label Content="NetBios Name:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="2" />
                        <Label Content="Entra ID Joined:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="3" />
                        <Label Content="Tenant Name:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="4"/>
                        <Label Name="lbTenantName" Content="Test" FontWeight="Normal" Grid.Column="1" Grid.Row="4" HorizontalAlignment="Right" Margin="0,0,-20,0" />
                        <Label Name="lbAzureAD_Joined" Content="Test" FontWeight="Normal" Grid.Column="1" Grid.Row="3" HorizontalAlignment="Right" Margin="0,0,-20,0"/>
                        <Label Name="lbComputerName" Content="Test" FontWeight="Normal" Grid.Column="1" Grid.Row="0" HorizontalAlignment="Right" Margin="0,0,-20,0"/>
                        <Label Name="lbDomainName" Content="Test" FontWeight="Normal" Grid.Column="1" Grid.Row="1" HorizontalAlignment="Right" Margin="0,0,-20,0"/>
                        <Label Name="lbNetBios" Content="Test" FontWeight="Normal" Grid.Column="1" Grid.Row="2" HorizontalAlignment="Right" Margin="0,0,-20,0"/>
                    </Grid>
                </Grid>
            </GroupBox>

            <!-- Domain Accounts ListView -->
            <Border BorderBrush="#E3E8E9" BorderThickness="1.2" CornerRadius="4" Margin="303,47,10,0" Grid.Row="0" Grid.ColumnSpan="2" Width="680">
                <Grid Margin="5,0,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition/>
                        <ColumnDefinition Width="0*"/>
                    </Grid.ColumnDefinitions>
                    <Grid.RowDefinitions>
                        <RowDefinition Height="180"/>
                    </Grid.RowDefinitions>
                    <Label HorizontalAlignment="Left" VerticalAlignment="Top" FontWeight="SemiBold" Foreground="#202D38" Content="Select a domain or Entra ID account to be migrated" Margin="0,5,0,0" Grid.RowSpan="2" Height="26" Width="297"/>
                    <!-- ListView -->
                    <ListView Name="lvProfileList" Grid.Row="1" BorderBrush="White" MinWidth="670" HorizontalAlignment="Left" Margin="0,36,0,0" Grid.ColumnSpan="2">
                        <ListView.View>
                            <GridView AllowsColumnReorder="True">
                                <GridView.ColumnHeaderContainerStyle>
                                    <Style TargetType="{x:Type GridViewColumnHeader}">
                                        <Setter Property="HorizontalContentAlignment" Value="Left"/>
                                        <Setter Property="BorderBrush" Value="White"/>
                                        <Setter Property="Background" Value="White"/>
                                        <Setter Property="FontSize" Value="11"/>
                                        <Setter Property="FontFamily" Value="Segoe UI"/>
                                        <Setter Property="FontWeight" Value="SemiBold"/>
                                        <Setter Property="Foreground" Value="#202D38"/>
                                        <Setter Property="Margin" Value="5,0,0,0"/>
                                    </Style>
                                </GridView.ColumnHeaderContainerStyle>
                                <GridViewColumn Header="System Accounts" DisplayMemberBinding="{Binding UserName}" Width="auto" />
                                <GridViewColumn Header="Last Login" DisplayMemberBinding="{Binding LastLogin}" Width="auto"/>
                                <GridViewColumn Header="Currently Active" DisplayMemberBinding="{Binding Loaded}" Width="auto" />
                                <GridViewColumn Header="Local Admin" DisplayMemberBinding="{Binding IsLocalAdmin}" Width="auto"/>
                                <GridViewColumn Header="Local Path" DisplayMemberBinding="{Binding LocalPath}" Width="auto"/>
                            </GridView>
                        </ListView.View>
                    </ListView>
                </Grid>
            </Border>

            <!-- Account Migration Information -->
            <GroupBox Header="" Style="{StaticResource NoHeaderGroupBoxStyle}" Grid.Row="1" Grid.Column="2" Margin="10,10,10,0">
                <Grid HorizontalAlignment="Left" VerticalAlignment="Top" Width="461">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                    </Grid.RowDefinitions>
                    <Label Content="Account Migration Information" Foreground="#202D38" HorizontalAlignment="Left" VerticalAlignment="Center" FontWeight="SemiBold" Margin="5,0,0,0"/>
                    <Grid Grid.Row="1">
                        <Label Content="Local Account Username" HorizontalAlignment="Left" Margin="5,5,0,0" VerticalAlignment="Top" TabIndex="2147483645" FontWeight="SemiBold" FontSize="11"/>
                        <Label Content="Local Account Password&#xD;&#xA;" HorizontalAlignment="Left" Margin="5,59,0,0" VerticalAlignment="Top" FontWeight="SemiBold" Height="27" FontSize="11"/>
                        <TextBox Name="tb_JumpCloudUserName" HorizontalAlignment="Left" Height="23" Margin="10,31,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="427"  FontWeight="SemiBold" FontSize="11" Style="{StaticResource RoundedTextBoxStyle}"/>
                        <TextBox Name="tb_tempPassword" Style="{StaticResource RoundedTextBoxStyle}" HorizontalAlignment="Left" Height="23" Margin="10,86,0,0" TextWrapping="Wrap" Text="" VerticalAlignment="Top" Width="427" FontWeight="SemiBold" FontSize="11"/>
                        <Image Name="img_localAccountInfo" Height="20" Margin="136,7,311,179" Width="14" Visibility="Visible" ToolTip="The value in this field should match a username in the JumpCloud console. A new local user account will be created with this username." />

                        <Image Name="img_localAccountValid" HorizontalAlignment="Left" Height="23" Margin="440,33,0,0" VerticalAlignment="Top" Width="14" ToolTip="Local account username can't be empty, contain spaces, already exist on the local system or match the local computer name." Visibility="Visible" />
                        <Image Name="img_localAccountPasswordInfo" Height="20" Margin="0,63,315,123" Width="14" Visibility="Visible" ToolTip="This temporary password is used on account creation. The password will be overwritten by the users jc password if autobound or manually bound in the console." HorizontalAlignment="Right"/>
                        <Image Name="img_localAccountPasswordValid" HorizontalAlignment="Left" Height="23" Margin="440,86,0,97" Width="14" Visibility="Visible"/>
                    </Grid>
                </Grid>
            </GroupBox>

            <!-- System Migration Information -->
            <GroupBox Header="" Style="{StaticResource NoHeaderGroupBoxStyle}" MinHeight="145" Margin="0,10,0,0" Grid.Row="1" Grid.Column="0">
                <Grid HorizontalAlignment="Left" Width="Auto" Height="Auto">
                    <Label FontWeight="SemiBold" Foreground="#202D38" Content="System Migration Options" Margin="5,0,328,211"/>
                    <TextBlock Name="lbl_connectKey" HorizontalAlignment="Left" Margin="10,111,0,0" Text="JumpCloud Connect Key :" VerticalAlignment="Top" TextDecorations="Underline" Foreground="#FF000CFF"/>
                    <PasswordBox Name="tb_JumpCloudConnectKey" HorizontalAlignment="Left" Height="23" Margin="10,132,0,0" VerticalAlignment="Top" Width="432"  Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False"/>
                    <TextBlock Name="lbl_apiKey" HorizontalAlignment="Left" Margin="10,164,0,0" Text="JumpCloud API Key :" VerticalAlignment="Top" TextDecorations="Underline" Foreground="#FF000CFF"/>
                    <PasswordBox Name="tb_JumpCloudAPIKey" HorizontalAlignment="Left" Height="23" Margin="10,185,0,0" VerticalAlignment="Top" Width="432"  Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False" />
                    <TextBlock Name="lbl_orgNameTitle" HorizontalAlignment="Left" Margin="10,219,0,0" Text="Organization Name:" VerticalAlignment="Top" FontWeight="Normal"/>
                    <TextBlock Name="lbl_selectOrgName" HorizontalAlignment="Right" Margin="0,164,44,0" Text="Select Different Organization" VerticalAlignment="Top" FontWeight="Normal" Visibility="Hidden" TextDecorations="Underline" Foreground="#FF000CFF"/>
                    <TextBlock Name="lbl_orgName" HorizontalAlignment="Left" Margin="124,219,0,0" Text="Not Currently Connected To A JumpCloud Organization" VerticalAlignment="Top" FontWeight="Normal"/>
                    <CheckBox Name="cb_forceReboot" Content="Force Reboot" HorizontalAlignment="Left" Margin="10,76,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                    <CheckBox Name="cb_installJCAgent" Content="Install JCAgent" HorizontalAlignment="Left" Margin="10,36,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                    <CheckBox Name="cb_bindAsAdmin" Content="Bind As Admin" HorizontalAlignment="Left" Margin="118,56,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False" IsEnabled="False"/>
                    <CheckBox Name="cb_leaveDomain" ToolTipService.ShowOnDisabled="True" Content="Leave Domain" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                    <CheckBox Name="cb_autobindJCUser" Content="Autobind JC User" HorizontalAlignment="Left" Margin="118,36,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False" />
                    <Image Name="img_connectKeyValid" HorizontalAlignment="Left" Height="23" Margin="446,135,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Connect Key must be 40chars &amp; not contain spaces" />
                    <Image Name="img_connectKeyInfo" HorizontalAlignment="Left" Height="14" Margin="152,114,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="The Connect Key provides you with a means of associating this system with your JumpCloud organization. The Key is used to deploy the agent to this system." />
                    <Image Name="img_apiKeyInfo" HorizontalAlignment="Left" Height="14" Margin="124,167,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Click the link for more info on how to obtain the api key. The API key must be from a user with at least 'Manager' or 'Administrator' privileges." />
                    <Image Name="img_apiKeyValid" HorizontalAlignment="Left" Height="23" Margin="446,188,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Correct error" />
                </Grid>
            </GroupBox>

            <!-- Migrate Button -->
            <Button Name="btn_migrateProfile" HorizontalAlignment="Right" VerticalAlignment="Top" Width="146" Height="30" IsEnabled="False" FontWeight="SemiBold" Content="Migrate Profile" Grid.Row="2" Grid.Column="1" Margin="0,10,10,0">
                <Button.Resources>
                    <Style TargetType="{x:Type Border}">
                        <Setter Property="CornerRadius" Value="3"/>
                    </Style>
                </Button.Resources>
            </Button>
        </Grid>
    </Grid>
</Window>
'@

    # Read XAML
    $reader = (New-Object System.Xml.XmlNodeReader $xaml)
    Try {
        $Form = [Windows.Markup.XamlReader]::Load($reader)
    } Catch {
        Write-Error "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered.";
        Exit;
    }
    #===========================================================================
    # Store Form Objects In PowerShell
    #===========================================================================
    $xaml.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]")  | ForEach-Object {
        New-Variable  -Name $_.Name -Value $Form.FindName($_.Name) -Force
    }
    $JCLogoImg.Source = Get-ImageFromB64 -ImageBase64 $JCLogoBase64
    $img_connectKeyInfo.Source = Get-ImageFromB64 -ImageBase64 $BlueBase64
    $img_connectKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
    $img_apiKeyInfo.Source = Get-ImageFromB64 -ImageBase64 $BlueBase64
    $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
    $img_localAccountInfo.Source = Get-ImageFromB64 -ImageBase64 $BlueBase64
    $img_localAccountValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
    $img_localAccountPasswordInfo.Source = Get-ImageFromB64 -ImageBase64 $BlueBase64
    $img_localAccountPasswordValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
    # Define misc static variables

    $WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
    Write-progress -Activity 'JumpCloud ADMU' -Status 'Loading JumpCloud ADMU. Please Wait.. Checking AzureAD Status..' -PercentComplete 25
    Write-ToLog 'Loading JumpCloud ADMU. Please Wait.. Checking AzureAD Status..'
    if ($WmiComputerSystem.PartOfDomain) {
        $WmiComputerDomain = Get-WmiObject -Class:('Win32_ntDomain')
        $secureChannelStatus = Test-ComputerSecureChannel

        $nbtstat = nbtstat -n
        foreach ($line in $nbtStat) {
            if ($line -match '^\s*([^<\s]+)\s*<00>\s*GROUP') {
                $NetBiosName = $matches[1]
            }
        }

        if ([System.String]::IsNullOrEmpty($WmiComputerDomain[0].DnsForestName) -and $secureChannelStatus -eq $false) {
            $DomainName = 'Fix Secure Channel'
        } else {
            $DomainName = [string]$WmiComputerDomain.DnsForestName
        }
        $NetBiosName = [string]$NetBiosName
    } elseif ($WmiComputerSystem.PartOfDomain -eq $false) {
        $DomainName = 'N/A'
        $NetBiosName = 'N/A'
        $secureChannelStatus = 'N/A'
    }
    if ((Get-CimInstance Win32_OperatingSystem).Version -match '10') {
        $AzureADInfo = dsregcmd.exe /status
        foreach ($line in $AzureADInfo) {
            if ($line -match "AzureADJoined : ") {
                $AzureADStatus = ($line.TrimStart('AzureADJoined : '))
            }
            if ($line -match "WorkplaceJoined : ") {
                $Workplace_join = ($line.TrimStart('WorkplaceJoined : '))
            }
            if ($line -match "TenantName : ") {
                $TenantName = ($line.TrimStart('WorkplaceTenantName : '))
            }
            if ($line -match "DomainJoined : ") {
                $AzureDomainStatus = ($line.TrimStart('DomainJoined : '))
            }
        }
    } else {
        $AzureADStatus = 'N/A'
        $Workplace_join = 'N/A'
        $TenantName = 'N/A'
    }

    # define return object:
    $FormResults = [PSCustomObject]@{
        InstallJCAgent      = $false
        AutoBindJCUser      = $false
        BindAsAdmin         = $false
        LeaveDomain         = $false
        ForceReboot         = $false
        SelectedUserName    = $null
        JumpCloudUserName   = $null
        TempPassword        = $null
        JumpCloudConnectKey = $null
        JumpCloudAPIKey     = $null
        JumpCloudOrgID      = $null
    }
    Write-Progress -Activity 'JumpCloud ADMU' -Status 'Loading JumpCloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..' -PercentComplete 50
    Write-ToLog 'Loading JumpCloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..'
    Write-Progress -Activity 'JumpCloud ADMU' -Status 'Loading JumpCloud ADMU. Please Wait.. Getting C:\ & Local Profile Data..' -PercentComplete 70
    Write-ToLog 'Loading JumpCloud ADMU. Please Wait.. Getting C:\ & Local Profile Data..'
    # Get Valid SIDs from the Registry and build user object
    $registryProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    $profileList = @()
    foreach ($profile in $registryProfiles) {
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
                Name              = Convert-SecurityIdentifier $listItem.PSChildName
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
                if ([string]::IsNullOrEmpty($($win32user.LastUseTime))) {
                    $user.LastLogin = "N/A"
                } else {
                    $user.LastLogin = [System.Management.ManagementDateTimeConverter]::ToDateTime($($win32user.LastUseTime)).ToUniversalTime().ToSTring($date_format)
                }
            }
        }
        # Get Admin Status
        try {
            $admin = Get-LocalGroupMember -Member "$($user.SID)" -Name "Administrators" -EA SilentlyContinue
        } catch {
            $user = Get-LocalGroupMember -Member "$($user.SID)" -Name "Users"
        }
        if ($admin) {
            $user.IsLocalAdmin = $true
        } else {
            $user.IsLocalAdmin = $false
        }
    }

    Write-Progress -Activity 'JumpCloud ADMU' -Status 'Loading JumpCloud ADMU. Please Wait.. Building Profile Group Box Query..' -PercentComplete 85
    Write-ToLog 'Loading JumpCloud ADMU. Please Wait.. Building Profile Group Box Query..'

    $Profiles = $users | Select-Object SID, RoamingConfigured, Loaded, IsLocalAdmin, LocalPath, LocalProfileSize, LastLogin, @{Name = "UserName"; EXPRESSION = { $_.Name } }
    Write-Progress -Activity 'JumpCloud ADMU' -Status 'Loading JumpCloud ADMU. Please Wait.. Done!' -PercentComplete 100
    Write-ToLog 'Loading JumpCloud ADMU. Please Wait.. Done!'

    #load UI Labels

    #SystemInformation
    $lbComputerName.Content = $WmiComputerSystem.Name

    #DomainInformation
    $lbDomainName.Content = $DomainName
    $lbNetBios.Content = $NetBiosName

    #AzureADInformation
    $lbAzureAD_Joined.Content = $AzureADStatus
    $lbTenantName.Content = $TenantName

    ## Form changes & interactions

    # Install JCAgent checkbox
    $cb_installJCAgent.Add_Checked( { Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser) })
    # $cb_installJCAgent.Add_Checked( { $InstallJCAgent = $true })
    $cb_installJCAgent.Add_Checked( { $tb_JumpCloudConnectKey.IsEnabled = $true })
    $cb_installJCAgent.Add_Checked( { $img_connectKeyInfo.Visibility = 'Visible' })
    $cb_installJCAgent.Add_Checked( { $img_connectKeyValid.Visibility = 'Visible' })
    $cb_installJCAgent.Add_Checked( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If (((Test-CharLen -len 40 -testString $tb_JumpCloudConnectKey.Password) -and (Test-HasNoSpace $tb_JumpCloudConnectKey.Password)) -eq $false) {
                #$tb_JumpCloudConnectKey.Tooltip = "Connect Key Must be 40chars & Not Contain Spaces"
                $tb_JumpCloudConnectKey.Background = "#FFC6CBCF"
                $tb_JumpCloudConnectKey.BorderBrush = "#FFF90000"
            } Else {
                $tb_JumpCloudConnectKey.Background = "white"
                $tb_JumpCloudConnectKey.Tooltip = $null
                $tb_JumpCloudConnectKey.FontWeight = "Normal"
                $tb_JumpCloudConnectKey.BorderBrush = "#FFC6CBCF"
            }

        })

    $cb_installJCAgent.Add_UnChecked( { Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser) })
    # $cb_installJCAgent.Add_Unchecked( { $InstallJCAgent = $false })
    $cb_installJCAgent.Add_Unchecked( { $tb_JumpCloudConnectKey.IsEnabled = $false })
    $cb_installJCAgent.Add_Unchecked( { $img_connectKeyInfo.Visibility = 'Hidden' })
    $cb_installJCAgent.Add_Unchecked( { $img_connectKeyValid.Visibility = 'Hidden' })
    $cb_installJCAgent.Add_Unchecked( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If (((Test-CharLen -len 40 -testString $tb_JumpCloudConnectKey.Password) -and (Test-HasNoSpace $tb_JumpCloudConnectKey.Password) -or ($cb_installJCAgent.IsEnabled)) -eq $false) {
                #$tb_JumpCloudConnectKey.Tooltip = "Connect Key Must be 40chars & Not Contain Spaces"
                $tb_JumpCloudConnectKey.Background = "#FFC6CBCF"
                $tb_JumpCloudConnectKey.BorderBrush = "#FFF90000"
            } Else {
                $tb_JumpCloudConnectKey.Background = "white"
                $tb_JumpCloudConnectKey.Tooltip = $null
                $tb_JumpCloudConnectKey.FontWeight = "Normal"
                $tb_JumpCloudConnectKey.BorderBrush = "#FFC6CBCF"
            }
        })


    # Autobind JC User checkbox
    $cb_autobindJCUser.Add_Checked( { Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser) })
    $cb_autobindJCUser.Add_Checked( { $tb_JumpCloudAPIKey.IsEnabled = $true })
    $cb_autobindJCUser.Add_Checked( { $img_apiKeyInfo.Visibility = 'Visible' })
    $cb_autobindJCUser.Add_Checked( { $img_apiKeyValid.Visibility = 'Visible' })
    $cb_autobindJCUser.Add_Checked( { $cb_bindAsAdmin.IsEnabled = $true })
    # $cb_bindAsAdmin.Add_Checked( { $BindAsAdmin = $true })
    $cb_autobindJCUser.Add_Checked( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If (Test-IsNotEmpty $tb_JumpCloudAPIKey.Password ) {
                #$tb_JumpCloudAPIKey.Tooltip = "API Key Must be 40chars & Not Contain Spaces"
                $tb_JumpCloudAPIKey.Background = "#FFC6CBCF"
                $tb_JumpCloudAPIKey.BorderBrush = "#FFF90000"
            } Else {
                $tb_JumpCloudAPIKey.Background = "white"
                $tb_JumpCloudAPIKey.Tooltip = $null
                $tb_JumpCloudAPIKey.FontWeight = "Normal"
                $tb_JumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
            }
        })


    $cb_autobindJCUser.Add_UnChecked( { Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser) })
    $cb_autobindJCUser.Add_Unchecked( { $tb_JumpCloudAPIKey.IsEnabled = $false })
    $cb_autobindJCUser.Add_Unchecked( { $img_apiKeyInfo.Visibility = 'Hidden' })
    $cb_autobindJCUser.Add_Unchecked( { $img_apiKeyValid.Visibility = 'Hidden' })
    $cb_autobindJCUser.Add_Unchecked( { $lbl_selectOrgName.Visibility = 'Hidden' })
    $cb_autobindJCUser.Add_Unchecked( { $cb_bindAsAdmin.IsEnabled = $false })
    $cb_autobindJCUser.Add_Unchecked( { $cb_bindAsAdmin.IsChecked = $false })
    # $cb_bindAsAdmin.Add_Unchecked( { $BindAsAdmin = $false })
    $cb_autobindJCUser.Add_Unchecked( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If ((!(Test-IsNotEmpty $tb_JumpCloudAPIKey.Password) -or ($cb_autobindJCUser.IsEnabled)) -eq $false) {
                #$tb_JumpCloudAPIKey.Tooltip = "API Key Must be 40chars & Not Contain Spaces"
                $tb_JumpCloudAPIKey.Background = "#FFC6CBCF"
                $tb_JumpCloudAPIKey.BorderBrush = "#FFF90000"
            } Else {
                $tb_JumpCloudAPIKey.Background = "white"
                $tb_JumpCloudAPIKey.Tooltip = $null
                $tb_JumpCloudAPIKey.FontWeight = "Normal"
                $tb_JumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
            }
        })


    # Leave Domain checkbox
    if (($AzureADStatus -eq 'Yes') -or ($AzureDomainStatus -eq 'Yes')) {
        $cb_leaveDomain.IsEnabled = $true
    } else {
        Write-ToLog "Device is not AzureAD Joined or Domain Joined. Leave Domain Checkbox Disabled."
        $cb_leaveDomain.IsEnabled = $false
    }

    $tb_JumpCloudUserName.add_LostFocus( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If ((Test-IsNotEmpty $tb_JumpCloudUserName.Text) -or (!(Test-HasNoSpace $tb_JumpCloudUserName.Text)) -or (Test-LocalUsername -username $tb_JumpCloudUserName.Text) -or (($tb_JumpCloudUserName.Text).Length -gt 20)) {
                $tb_JumpCloudUserName.Background = "#FFC6CBCF"
                $tb_JumpCloudUserName.BorderBrush = "#FFF90000"
                $img_localAccountValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                $img_localAccountValid.ToolTip = "Local account username can not:`nBe empty or contain spaces.`nAlready exist on the local system.`nMatch the local computer name.`nContain more than 20 characters."
            } Else {
                $tb_JumpCloudUserName.Background = "white"
                $tb_JumpCloudUserName.FontWeight = "Normal"
                $tb_JumpCloudUserName.BorderBrush = "#FFC6CBCF"
                $img_localAccountValid.Source = Get-ImageFromB64 -ImageBase64 $ActiveBase64
                $img_localAccountValid.ToolTip = $null
            }
        })

    # Validate Connect Key
    $tb_JumpCloudConnectKey.Add_PasswordChanged( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If (((Test-CharLen -len 40 -testString $tb_JumpCloudConnectKey.Password) -and (Test-HasNoSpace $tb_JumpCloudConnectKey.Password)) -eq $false) {
                $tb_JumpCloudConnectKey.Background = "#FFC6CBCF"
                $tb_JumpCloudConnectKey.BorderBrush = "#FFF90000"
                $img_connectKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                $img_connectKeyValid.ToolTip = "Connect Key must be 40chars & not contain spaces."
            } Else {
                $tb_JumpCloudConnectKey.Background = "white"
                $tb_JumpCloudConnectKey.FontWeight = "Normal"
                $tb_JumpCloudConnectKey.BorderBrush = "#FFC6CBCF"
                $img_connectKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ActiveBase64
                $img_connectKeyValid.ToolTip = $null
            }
        })

    # Validate API KEY
    $tb_JumpCloudAPIKey.Add_PasswordChanged( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If (Test-IsNotEmpty $tb_JumpCloudAPIKey.Password) {
                $tb_JumpCloudAPIKey.Background = "#FFC6CBCF"
                $tb_JumpCloudAPIKey.BorderBrush = "#FFF90000"
                $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                $img_apiKeyValid.ToolTip = "Please enter a valid JumpCloud API Key"

            } Else {
                # Get org name/ id
                try {
                    $OrgSelection, $mtpAdmin = Get-MtpOrganization -ApiKey $tb_JumpCloudAPIKey.Password -inputType
                    $lbl_orgName.Text = "$($OrgSelection[1])"
                    $script:selectedOrgID = "$($OrgSelection[0])"
                    if ($mtpAdmin) {
                        # only display this text label if a MTP admin entered their API key
                        $lbl_selectOrgName.Visibility = 'Visible'
                    }
                    $tb_JumpCloudAPIKey.Background = "white"
                    $tb_JumpCloudAPIKey.Tooltip = $null
                    $tb_JumpCloudAPIKey.FontWeight = "Normal"
                    $tb_JumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
                    $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ActiveBase64
                    $img_apiKeyValid.ToolTip = $null
                    Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -selectedOrgID($script:selectedOrgID) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
                } catch {
                    $lbl_selectOrgName.Visibility = 'Hidden'
                    $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                    $img_apiKeyValid.ToolTip = "Please enter a valid JumpCloud API Key"
                    $OrgSelection = ""
                    $lbl_orgName.Text = ""
                    $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                    Write-ToLog "MTP KEY MAY BE WRONG"
                }
            }
        })

    # Validate Temp Password
    $tb_tempPassword.add_LostFocus( {
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            If ((Test-IsNotEmpty $tb_tempPassword.Text) -or (-NOT (Test-HasNoSpace $tb_tempPassword.Text))) {
                $tb_tempPassword.Background = "#FFC6CBCF"
                $tb_tempPassword.BorderBrush = "#FFF90000"
                $img_localAccountPasswordValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                $img_localAccountPasswordValid.ToolTip = "Local Account Temp Password should:`nNot be empty or contain spaces.`n should also meet local password policy requirements on the system."
            } Else {
                $tb_tempPassword.Background = "white"
                $tb_tempPassword.Tooltip = $null
                $tb_tempPassword.FontWeight = "Normal"
                $tb_tempPassword.BorderBrush = "#FFC6CBCF"
                $img_localAccountPasswordValid.Source = Get-ImageFromB64 -ImageBase64 $ActiveBase64
                $img_localAccountPasswordValid.ToolTip = $null
            }
        })

    # Change button when profile selected
    $lvProfileList.Add_SelectionChanged( {
            $SelectedUserName = $($lvProfileList.SelectedItem.username)
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
            Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            try {
                $SelectedUserSID = ((New-Object System.Security.Principal.NTAccount($SelectedUserName)).Translate( [System.Security.Principal.SecurityIdentifier]).Value)
            } catch {
                $SelectedUserSID = $SelectedUserName
            }
            $hku = ('HKU:\' + $SelectedUserSID)
            if (Test-Path -Path $hku) {
                $btn_migrateProfile.IsEnabled = $false
                $tb_JumpCloudUserName.IsEnabled = $false
                $tb_tempPassword.IsEnabled = $false
            } else {
                $tb_JumpCloudUserName.IsEnabled = $true
                $tb_tempPassword.IsEnabled = $true
            }
        })
    $SelectedUserName = $($lvProfileList.SelectedItem.username)

    # Validate Migrate Profile & return $formResults
    $btn_migrateProfile.Add_Click( {
            if ($tb_JumpCloudAPIKey.Password -And $tb_JumpCloudUserName.Text -And $cb_autobindJCUser.IsChecked) {
                # If text field is default/ not 40 chars
                if (!(Test-CharLen -len 40 -testString $tb_JumpCloudConnectKey.Password)) {
                    # Validate the the JumpCLoud Agent Conf File exists:
                    $keyResult = Test-JumpCloudSystemKey -WindowsDrive $(Get-WindowsDrive)
                    if (!$keyResult) {
                        # If we catch here, the system conf file does not exist. User is prompted to enter connect key; log below
                        Write-ToLog "The JumpCloud agent has not be registered on this system, to please specify a valid Connect Key to continue."
                        return
                    }
                } else {
                    Write-ToLog "ConnectKey is populated, JumpCloud agent will be installed"
                }

                $testResult, $JumpCloudUserId, $JCSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $tb_JumpCloudAPIKey.Password -JumpCloudOrgID $script:selectedOrgID -Username $tb_JumpCloudUserName.Text -Prompt $true
                if ($testResult) {
                    Write-ToLog "Matched $($tb_JumpCloudUserName.Text) with user in the JumpCloud Console"
                } else {
                    Write-ToLog "$($tb_JumpCloudUserName.Text) not found in the JumpCloud console"
                    return
                }
                if ( -not [string]::IsNullOrEmpty($JCSystemUsername) ) {
                    # Regex to get the username from the domain\username string and compare it to JCSystemUsername
                    #Get all the local users
                    $registryProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                    $profileList = @()
                    foreach ($profile in $registryProfiles) {
                        $profileList += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath, @{ Name = "username"; Expression = { $sysUsername = Convert-SecurityIdentifier -sid $_.PSChildName; $sysUsername.Split('\')[1] } }
                    }
                    # If the JumpCloud found username was identified to exist locally, throw message
                    if ($JCSystemUsername -in $profileList.username) {
                        # Create a pop up that warns user then press ok to continue
                        Write-ToLog "JCSystemUsername $($JCSystemUsername) is the same as the another profile on this system"
                        $wshell = New-Object -ComObject Wscript.Shell
                        $message = "The JumpCloud User: $($tb_JumpCloudUserName.Text) has a local account username of: $($JCSystemUsername). A local account already exists on this system with username: $($JCSystemUsername), please consider removing either the local account on this system or removing the local user account field from the JumpCloud user."
                        $var = $wshell.Popup("$message", 0, "JumpCloud SystemUsername and Local Computer Username Validation", 0)
                        # the user can not continue with migration at this stage
                        return
                    }
                    $wshell = New-Object -ComObject Wscript.Shell
                    $message = "The JumpCloud User: $($tb_JumpCloudUserName.Text) has a local account username of: $($JCSystemUsername). After migration $($SelectedUserName) would be migrated and accessible with the local account username of: $($JCSystemUsername) Would you like to continue?"
                    $var = $wshell.Popup("$message", 0, "JumpCloud Local User Validation", 64 + 4)
                    # If user selects yes then migrate the local user profile to the JumpCloud User

                    if ($var -eq 6) {
                        Write-ToLog -Message "User selected 'Yes', continuing with migration of $($SelectedUserName) to $($JCSystemUsername)"
                    } else {
                        Write-ToLog -Message "User selected 'No', returning to form"
                        return
                    }
                } else {
                    Write-ToLog "User $($tb_JumpCloudUserName.Text) does not have a local account on this system"
                }
            }
            # Build FormResults object
            Write-ToLog "Building Form Results"

            if ([System.String]::IsNullOrEmpty($SelectedUserName)) {
                # TODO: I've broken the conversion for the username here, need to figure out why this no longer works.
                $SelectedUserName = $($lvProfileList.SelectedItem.username)
            }

            # Set the options selected/ inputs to the $formResults object
            $FormResults.InstallJCAgent = $cb_installJCAgent.IsChecked
            $FormResults.AutoBindJCUser = $cb_autobindJCUser.IsChecked
            $FormResults.BindAsAdmin = $cb_bindAsAdmin.IsChecked
            $FormResults.LeaveDomain = $cb_leaveDomain.IsChecked
            $FormResults.ForceReboot = $cb_forceReboot.IsChecked
            $FormResults.SelectedUserName = $SelectedUserName
            $FormResults.JumpCloudUserName = $tb_JumpCloudUserName.Text
            $FormResults.TempPassword = $tb_tempPassword.Text
            $FormResults.JumpCloudConnectKey = $tb_JumpCloudConnectKey.Password
            $FormResults.JumpCloudAPIKey = $tb_JumpCloudAPIKey.Password
            $FormResults.JumpCloudOrgID = $script:selectedOrgID
            # Close form
            $Form.Close()
        })

    # $tb_JumpCloudUserName.add_GotFocus( {
    #         $tb_JumpCloudUserName.Text = ""
    #     })

    # $tb_JumpCloudConnectKey.add_GotFocus( {
    #         $tb_JumpCloudConnectKey.Password = ""
    #     })

    # $tb_JumpCloudAPIKey.add_GotFocus( {
    #         $tb_JumpCloudAPIKey.Password = ""
    #     })



    # lbl_connectKey link - Mouse button event
    $lbl_connectKey.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://console.jumpcloud.com/#/systems/new') })

    # lbl_apiKey link - Mouse button event
    $lbl_apiKey.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://support.jumpcloud.com/support/s/article/jumpcloud-apis1') })

    # Add controls for to select a different org
    $lbl_selectOrgName.Add_PreviewMouseDown({
            try {
                # Get MTP Organization returns, the org selected ($orgSelection) and whether the user is an MTP admin or not ($mtpAdmin)
                $OrgSelection, $mtpAdmin = Get-MtpOrganization -ApiKey $tb_JumpCloudAPIKey.Password -inputType
                $lbl_orgName.Text = "$($OrgSelection[1])"
                $script:selectedOrgID = "$($OrgSelection[0])"
                if ($mtpAdmin) {
                    # only display this text label if a MTP admin entered their API key
                    $lbl_selectOrgName.Visibility = 'Visible'
                }
                $tb_JumpCloudAPIKey.Background = "white"
                $tb_JumpCloudAPIKey.Tooltip = $null
                $tb_JumpCloudAPIKey.FontWeight = "Normal"
                $tb_JumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
                $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ActiveBase64
                $img_apiKeyValid.ToolTip = $null
                Test-MigrationButton -tb_JumpCloudUserName:($tb_JumpCloudUserName) -tb_JumpCloudConnectKey:($tb_JumpCloudConnectKey) -tb_tempPassword:($tb_tempPassword) -lvProfileList:($lvProfileList) -tb_JumpCloudAPIKey:($tb_JumpCloudAPIKey) -selectedOrgID($script:selectedOrgID) -cb_installJCAgent:($cb_installJCAgent) -cb_autobindJCUser:($cb_autobindJCUser)
            } catch {
                $btn_migrateProfile.IsEnabled = $false
                $lbl_selectOrgName.Visibility = 'Hidden'
                $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                $img_apiKeyValid.ToolTip = "Please enter a valid JumpCloud API Key"
                $OrgSelection = ""
                $lbl_orgName.Text = ""
                $img_apiKeyValid.Source = Get-ImageFromB64 -ImageBase64 $ErrorBase64
                Write-ToLog "MTP KEY MAY BE WRONG"
            }
        })

    # move window
    $Form.Add_MouseLeftButtonDown( {
            $Form.DragMove()
        })
    # allow form to be clicked and remove focus from text fields
    Function RefreshData {
        $Test = "Testing" | Out-Gridview
    }
    $Form.Add_PreviewMouseDown({
            $grid1.Focus()
        })

    # exit and close form
    $Form.Add_Closing({
            return
        })
    # Put the list of profiles in the profile box
    $Profiles | ForEach-Object { $lvProfileList.Items.Add($_) | Out-Null }
    #===========================================================================
    # Shows the form & allow move
    #===========================================================================

    $Form.ShowDialog()

    # if the migrate button is enabled and it is clicked, send formResults to Start-Migration
    If (($btn_migrateProfile.IsEnabled -eq $true) -AND $btn_migrateProfile.Add_Click) {
        Return $FormResults
    }
}