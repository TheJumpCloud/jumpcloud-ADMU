# Hides Powershell Window
$ShowWindowAsync = Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32ShowWindowAsync" -Namespace "Win32Functions" -PassThru
# PID of the current process
# Get PID of the current process
$FormWindowPIDHandle = (Get-Process -Id $pid).MainWindowHandle
$ShowWindowAsync::ShowWindowAsync($FormWindowPIDHandle, 0) | Out-Null
# PID
Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Loading ADMU GUI..'
# Base64 Encoded Strings of our Images
$JCLogoBase64 = "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"
$ErrorBase64 = "iVBORw0KGgoAAAANSUhEUgAAABIAAAASCAYAAABWzo5XAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAFiSURBVHgBpVPNSsNAEJ4ZzwWv/lKfoPUN2oOl3lYKelAoPpkIelBQ4smih8YnMI8QqlQbL0JbT2bH2di0MXFD2n6w7OzMzscwMx/CP3hpqhoBtcWsySlHTmYPEL1Q67vtB8dJ52Dy8dZUZQY8k1ODfPgEur7WcfwM0eueqiJRVzyrUAQMn6x1ffPR8aZEphLN9JwmKR0fQunkKLKHF1cwvLzOkBHqXVMZmbeGOSpJQnJMK4xJvUZLQdzQBWD6GQ2HSCvbpzAIZvbgw0pGsNImZKxAAYTjcU6UZV0Qqrbw9/usCs4lgjLlRcMgQTTKJQJD5EMB6NGXPShbTwz8ZIuHg0SzE43PQKSDE111YRkwqWiz+82Drk1f6/c30d3fb9lo/I3O7U7UbAQ+NesOc1ciEhHx/nJMsKxop+M3DiNAKDBFGZBr/sYkfypKotdQiggVMlRkIvHC+nJcDfp8q+O46Zwfa3qRu77hWMMAAAAASUVORK5CYII="
$ActiveBase64 = "iVBORw0KGgoAAAANSUhEUgAAABIAAAASCAYAAABWzo5XAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAGKSURBVHgBlZRPTsJQEMbfTBvccgTcKYFQlxJM2hvUEygnID2CJ6jKAZQTgCcoorK1Cf5hZ4/A1oQ3Y98j1FKLbWfTvnn9fp3ON68gcqL15NtsGhfIbLOAxibLITOECPJh0fUmWQ2kF0eB3zBreCcAbPFPsBCR/JbO0vGiP6Bm4FtYM4I4UxflYgVC9rfVwW8lxmsFSAIjks5HzwtRrYyDSpWko46Avq6oPRu6bPK4jIoFR0x0HotVH61kQ0oHCcktC5FA+jOIqb+zpxwGwE6eKA+yPPUi1U9AY5wR2CiArXQOiEfv3cGhuuZBVD9jhxo7mniN2WqkoGt1XfQGl4L5qgiSwNrz2y/e3Uws3SaKIMwcIgl+zOTriEbQfPatMhAdqI8O3edsadjxfOgWQlRFxBM92a2Xm6DofO2FxGYoc3Sz1xjPBYuVqBrMK2WGutUg5QqxdCrBNpC+0iYgFcqlNcqT7DDugUzj6XY+U/8lyHuuPfNdMtEFFp3tmYL4BQQwhbUcvZ1506zmB49h1CYDMPPcAAAAAElFTkSuQmCC"
$BlueBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAMCAYAAABWdVznAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAElSURBVHgBbVE7TsNAEH2z+dQ+wnKCmIY6nICCIEIXdymIYk4AnCBBEETpVBQWSjgBpEM0+Ag+ghGiQIl3GH/BcUaa1erNe292ZglFuAsLGzMGmwGItCCRZACGh1lvXtAoPYcLjYZ5AbEuDZg8wHRTMfEUtycXCax2kolCzI4dud3kYhcjf5J1GD1NwOyiHq+StqT1B/GhEnK3yjNzGLOPzdqpkhM+bJW7FBGBFMPEEZpNXW+qOgrZNoqwxEXj4SwUu0GNT/yZCIKttl5e7WyZJbUPEfB1BWx9PaebA63wfwbmEPF61cC7H+KgtyeEbBbT/oHisdz61ecYB/f9NyqBc/9K0EvUQ54VO7g7Xaa6Smn4qNFsHclH2cmAst4A7e8lpk45yy8GxWbP/ZW8WwAAAABJRU5ErkJggg=="

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void][reflection.assembly]::LoadWithPartialName("System.Windows.Forms")
# Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing, System.Drawing
function DecodeBase64Image {
    param (
        [Parameter(Mandatory = $true)]
        [String]$ImageBase64
    )
    # Parameter help description
    $ObjBitmapImage = New-Object System.Windows.Media.Imaging.BitmapImage #Provides a specialized BitmapSource that is optimized for loading images using Extensible Application Markup Language (XAML).
    $ObjBitmapImage.BeginInit() #Signals the start of the BitmapImage initialization.
    $ObjBitmapImage.StreamSource = [System.IO.MemoryStream][System.Convert]::FromBase64String($ImageBase64) #Creates a stream whose backing store is memory.
    $ObjBitmapImage.EndInit() #Signals the end of the BitmapImage initialization.
    $ObjBitmapImage.Freeze() #Makes the current object unmodifiable and sets its IsFrozen property to true.
    $ObjBitmapImage
}
function show-mtpSelection {
    [OutputType([object[]])]
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Object]
        $Orgs
    )
    begin {
        $Prompt = 'Please Select A JumpCloud MTP:'
        $Title = 'MTP Organization Selection'
        # define a data table to store org names/ org ids
        $datatable = New-Object system.Data.DataTable
        #Define Columns
        $col1 = New-Object system.Data.DataColumn "Value", ([string])
        $col2 = New-Object system.Data.DataColumn "Text", ([string])
        #add columns to datatable
        $datatable.columns.add($col1)
        $datatable.columns.add($col2)
        # Define Buttons:
        $okButton = [System.Windows.Forms.Button]@{
            Location     = '290,12'
            Size         = '60,22'
            Text         = 'OK'
            DialogResult = [System.Windows.Forms.DialogResult]::OK
        }
        $cancelButton = [System.Windows.Forms.Button]@{
            Location     = '290,40'
            Size         = '60,22'
            Text         = 'Cancel'
            DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        }
        # label for the form
        $label = [System.Windows.Forms.Label]@{
            AutoSize    = $true
            Location    = '10,10'
            Size        = '240,20'
            MaximumSize = '250,0'
            Text        = $Prompt
        }
        $dynamicLabel = [System.Windows.Forms.Label]@{
            AutoSize    = $true
            Location    = '10,30'
            Size        = '240,20'
            MaximumSize = '250,0'
            Text        = ''
        }
        foreach ($org in $orgs) {
            #Create a row
            $name = New-Variable -Name "row_$($org._id)"
            $name = $datarow1 = $datatable.NewRow()
            #Enter data in the row
            $name.Text = "$($org.DisplayName)"
            $name.Value = "$($org._id)"
            #Add the row to the datatable
            $datatable.Rows.Add($name)
        }
        #create a combobox
        $comboBox = [System.Windows.Forms.ComboBox]@{
            Location      = '10,90'
            AutoSize      = $true
            MaximumSize   = '500,0'
            # MaximumSize   = '335,0'
            DropDownStyle = "DropDownList"
        }
        $SelectBox = [System.Windows.Forms.Form]@{
            Text            = $Title
            Size            = '369,159'
            # Size            = '369,159'
            StartPosition   = 'CenterScreen'
            AcceptButton    = $okButton
            CancelButton    = $cancelButton
            FormBorderStyle = 'FixedDialog'
            MinimizeBox     = $false
            MaximizeBox     = $false
        }
    }
    process {
        #clear combo before we bind it
        $combobox.Items.Clear()

        #bind combobox to datatable
        $combobox.ValueMember = "Value"
        $combobox.DisplayMember = "Text"
        $combobox.Datasource = $datatable

        #add combobox to form
        $SelectBox.Controls.Add($combobox)

        #show form
        $SelectBox.Controls.AddRange(@($okButton, $cancelButton, $label, $dynamicLabel))
        $SelectBox.Topmost = $true
        $SelectBox.Add_Shown({ $comboBox.Select() })

    }
    end {
        $combobox.Add_SelectedIndexChanged({
                #output the selected value and text
                $dynamicLabel.Text = "OrgName: $($combobox.SelectedItem['Text'])"
                $dynamicLabel.Refresh();
                # write-host $combobox.SelectedItem["Value"] $combobox.SelectedItem["Text"]
            })
        $result = $SelectBox.ShowDialog()
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            # return id of the org we selected
            return $combobox.SelectedItem["Value"], $combobox.SelectedItem["Text"]
        } else {
            return $null
        }
    }
}
# Set source here. Take note in the XAML as to where the variable name was taken.

#==============================================================================================
# XAML Code - Imported from Visual Studio WPF Application
#==============================================================================================
[void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
[xml]$XAML = @'
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="JumpCloud ADMU 2.7.9"
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
    <Grid>
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
            <Image Name="JCLogoImg" Source="C:\Users\kmara\Downloads\JC oceanblue tm.png" Height="23" VerticalAlignment="Top" Margin="0,10,258,0" Width="auto" HorizontalAlignment="Left"/>

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
                        <TextBox Name="tbJumpCloudUserName" HorizontalAlignment="Left" Height="23" Margin="10,31,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="427"  FontWeight="SemiBold" FontSize="11" Style="{StaticResource RoundedTextBoxStyle}"/>
                        <TextBox Name="tbTempPassword" Style="{StaticResource RoundedTextBoxStyle}" HorizontalAlignment="Left" Height="23" Margin="10,86,0,0" TextWrapping="Wrap" Text="Temp123!Temp123!" VerticalAlignment="Top" Width="427" FontWeight="SemiBold" FontSize="11"/>
                        <Image Name="img_localaccount_info" Height="20" Margin="136,7,311,179" Width="14" Visibility="Visible" ToolTip="The value in this field should match a username in the jc console. A new local user account will be created with this username." />

                        <Image Name="img_localaccount_valid" HorizontalAlignment="Left" Height="23" Margin="440,33,0,0" VerticalAlignment="Top" Width="14" ToolTip="Local account username can't be empty, contain spaces, already exist on the local system or match the local computer name." Visibility="Visible" />
                        <Image Name="img_localaccount_password_info" Height="20" Margin="0,63,315,123" Width="14" Visibility="Visible" ToolTip="This temporary password is used on account creation. The password will be overwritten by the users jc password if autobound or manually bound in the console." HorizontalAlignment="Right"/>
                        <Image Name="img_localaccount_password_valid" HorizontalAlignment="Left" Height="23" Margin="440,86,0,97" Width="14" Visibility="Visible"/>
                    </Grid>
                </Grid>
            </GroupBox>

            <!-- System Migration Information -->
            <GroupBox Header="" Style="{StaticResource NoHeaderGroupBoxStyle}" MinHeight="145" Margin="0,10,0,0" Grid.Row="1" Grid.Column="0">
                <Grid HorizontalAlignment="Left" Width="Auto" Height="Auto">
                    <Label FontWeight="SemiBold" Foreground="#202D38" Content="System Migration Options" Margin="5,0,328,211"/>
                    <TextBlock Name="lbl_connectkey" HorizontalAlignment="Left" Margin="10,111,0,0" Text="JumpCloud Connect Key :" VerticalAlignment="Top" TextDecorations="Underline" Foreground="#FF000CFF"/>
                    <PasswordBox Name="tbJumpCloudConnectKey" HorizontalAlignment="Left" Height="23" Margin="10,132,0,0" VerticalAlignment="Top" Width="432"  Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False"/>
                    <TextBlock Name="lbl_apikey" HorizontalAlignment="Left" Margin="10,164,0,0" Text="JumpCloud API Key :" VerticalAlignment="Top" TextDecorations="Underline" Foreground="#FF000CFF"/>
                    <PasswordBox Name="tbJumpCloudAPIKey" HorizontalAlignment="Left" Height="23" Margin="10,185,0,0" VerticalAlignment="Top" Width="432"  Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False" />
                    <TextBlock Name="lbl_orgNameTitle" HorizontalAlignment="Left" Margin="10,219,0,0" Text="Organization Name:" VerticalAlignment="Top" FontWeight="Normal"/>
                    <TextBlock Name="lbl_orgName" HorizontalAlignment="Left" Margin="124,219,0,0" Text="Not Currently Connected To A JumpCloud Organization" VerticalAlignment="Top" FontWeight="Normal"/>
                    <CheckBox Name="cb_forcereboot" Content="Force Reboot" HorizontalAlignment="Left" Margin="10,76,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                    <CheckBox Name="cb_installjcagent" Content="Install JCAgent" HorizontalAlignment="Left" Margin="10,36,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                    <CheckBox Name="cb_bindAsAdmin" Content="Bind As Admin" HorizontalAlignment="Left" Margin="118,56,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False" IsEnabled="False"/>
                    <CheckBox Name="cb_leavedomain" ToolTipService.ShowOnDisabled="True" Content="Leave Domain" HorizontalAlignment="Left" Margin="10,56,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                    <CheckBox Name="cb_autobindjcuser" Content="Autobind JC User" HorizontalAlignment="Left" Margin="118,36,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False" />
                    <Image Name="img_ckey_valid" HorizontalAlignment="Left" Height="23" Margin="446,135,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Connect Key must be 40chars &amp; not contain spaces" />
                    <Image Name="img_ckey_info" HorizontalAlignment="Left" Height="14" Margin="152,114,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="The Connect Key provides you with a means of associating this system with your JumpCloud organization. The Key is used to deploy the agent to this system." />
                    <Image Name="img_apikey_info" HorizontalAlignment="Left" Height="14" Margin="124,167,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Click the link for more info on how to obtain the api key. The API key must be from a user with at least 'Manager' or 'Administrator' privileges." />
                    <Image Name="img_apikey_valid" HorizontalAlignment="Left" Height="23" Margin="446,188,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Correct error" />
                </Grid>
            </GroupBox>

            <!-- Migrate Button -->
            <Button Name="bMigrateProfile" HorizontalAlignment="Right" VerticalAlignment="Top" Width="146" Height="30" IsEnabled="False" FontWeight="SemiBold" Content="Migrate Profile" Grid.Row="2" Grid.Column="1" Margin="0,10,10,0">
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
$JCLogoImg.Source = DecodeBase64Image -ImageBase64 $JCLogoBase64
$img_ckey_info.Source = DecodeBase64Image -ImageBase64 $BlueBase64
$img_ckey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
$img_apikey_info.Source = DecodeBase64Image -ImageBase64 $BlueBase64
$img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
$img_localaccount_info.Source = DecodeBase64Image -ImageBase64 $BlueBase64
$img_localaccount_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
$img_localaccount_password_info.Source = DecodeBase64Image -ImageBase64 $BlueBase64
$img_localaccount_password_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
# Define misc static variables

$WmiComputerSystem = Get-WmiObject -Class:('Win32_ComputerSystem')
Write-progress -Activity 'Jumpcloud ADMU' -Status 'Loading Jumpcloud ADMU. Please Wait.. Checking AzureAD Status..' -PercentComplete 25
Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Checking AzureAD Status..'
if ($WmiComputerSystem.PartOfDomain) {
    $WmiComputerDomain = Get-WmiObject -Class:('Win32_ntDomain')
    $securechannelstatus = Test-ComputerSecureChannel

    $nbtstat = nbtstat -n
    foreach ($line in $nbtStat) {
        if ($line -match '^\s*([^<\s]+)\s*<00>\s*GROUP') {
            $NetBiosName = $matches[1]
        }
    }

    if ([System.String]::IsNullOrEmpty($WmiComputerDomain[0].DnsForestName) -and $securechannelstatus -eq $false) {
        $DomainName = 'Fix Secure Channel'
    } else {
        $DomainName = [string]$WmiComputerDomain.DnsForestName
    }
    $NetBiosName = [string]$NetBiosName
} elseif ($WmiComputerSystem.PartOfDomain -eq $false) {
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
            $TenantName = ($line.trimstart('WorkplaceTenantName : '))
        }
        if ($line -match "DomainJoined : ") {
            $AzureDomainStatus = ($line.trimstart('DomainJoined : '))
        }
    }
} else {
    $AzureADStatus = 'N/A'
    $Workplace_join = 'N/A'
    $TenantName = 'N/A'
}

$FormResults = [PSCustomObject]@{ }
Write-Progress -Activity 'Jumpcloud ADMU' -Status 'Loading Jumpcloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..' -PercentComplete 50
Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Verifying Local Accounts & Group Membership..'
Write-Progress -Activity 'Jumpcloud ADMU' -Status 'Loading Jumpcloud ADMU. Please Wait.. Getting C:\ & Local Profile Data..' -PercentComplete 70
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
    # Get Profile Size
    # $largeprofile = Get-ChildItem $($user.LocalPath) -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum length | Select-Object -ExpandProperty Sum
    # $largeprofile = [math]::Round($largeprofile / 1MB, 0)
    # $user.LocalProfileSize = $largeprofile
}

Write-Progress -Activity 'Jumpcloud ADMU' -Status 'Loading Jumpcloud ADMU. Please Wait.. Building Profile Group Box Query..' -PercentComplete 85
Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Building Profile Group Box Query..'

$Profiles = $users | Select-Object SID, RoamingConfigured, Loaded, IsLocalAdmin, LocalPath, LocalProfileSize, LastLogin, @{Name = "UserName"; EXPRESSION = { $_.Name } }
Write-Progress -Activity 'Jumpcloud ADMU' -Status 'Loading Jumpcloud ADMU. Please Wait.. Done!' -PercentComplete 100
Write-ToLog 'Loading Jumpcloud ADMU. Please Wait.. Done!'

#load UI Labels

#SystemInformation
$lbComputerName.Content = $WmiComputerSystem.Name

#DomainInformation
$lbDomainName.Content = $DomainName
$lbNetBios.Content = $NetBiosName

#AzureADInformation
$lbAzureAD_Joined.Content = $AzureADStatus
$lbTenantName.Content = $TenantName
Function Test-Button([object]$tbJumpCloudUserName, [object]$tbJumpCloudConnectKey, [object]$tbTempPassword, [object]$lvProfileList, [object]$tbJumpCloudAPIKey) {
    If (![System.String]::IsNullOrEmpty($lvProfileList.SelectedItem.UserName)) {
        If (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) -and (($($tbJumpCloudUserName.Text).length) -le 20) `
                -and ((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Password) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Password) -and ($cb_installjcagent.IsChecked -eq $true))`
                -and (!(Test-IsNotEmpty $tbJumpCloudAPIKey.Password) -and ($cb_autobindjcuser.IsChecked -eq $true))`
                -and ((Test-CharLen -len 24 -testString $Env:selectedOrgID) -and (Test-HasNoSpace $Env:selectedOrgID) -and ($cb_autobindjcuser.IsChecked -eq $true))`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(($($lvProfileList.selectedItem.Username) -split '\\')[0] -match $WmiComputerSystem.Name)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } ElseIf (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) -and (($($tbJumpCloudUserName.Text).length) -le 20) `
                -and ((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Password) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Password) -and ($cb_installjcagent.IsChecked -eq $true) -and ($cb_autobindjcuser.IsChecked -eq $false))`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } ElseIf (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) -and (($($tbJumpCloudUserName.Text).length) -le 20) `
                -and (!(Test-IsNotEmpty $tbJumpCloudAPIKey.Password) -and ($cb_autobindjcuser.IsChecked -eq $true) -and ($cb_installjcagent.IsChecked -eq $false))`
                -and ((Test-CharLen -len 24 -testString $Env:selectedOrgID) -and (Test-HasNoSpace $Env:selectedOrgID) -and ($cb_autobindjcuser.IsChecked -eq $true) -and ($cb_installjcagent.IsChecked -eq $false))`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } Elseif (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) -and (($($tbJumpCloudUserName.Text).length) -le 20)`
                -and ($cb_installjcagent.IsChecked -eq $false) -and ($cb_autobindjcuser.IsChecked -eq $false)`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } Elseif ($lvProfileList.selectedItem.Username -eq 'UNKNOWN ACCOUNT') {
            # Unmatched Profile, prevent migration
            $script:bMigrateProfile.IsEnabled = $false
            Return $false
        } elseif (($($lvProfileList.selectedItem.Username) -split '\\')[0] -match $WmiComputerSystem.Name) {
            $script:bMigrateProfile.IsEnabled = $false
            Return $false
        } Else {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $false
            Return $false
        }
    } Else {
        $script:bMigrateProfile.IsEnabled = $false
        Return $false
    }
}

## Form changes & interactions

# Install JCAgent checkbox
$script:InstallJCAgent = $false
$cb_installjcagent.Add_Checked( { Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey) })
$cb_installjcagent.Add_Checked( { $script:InstallJCAgent = $true })
$cb_installjcagent.Add_Checked( { $tbJumpCloudConnectKey.IsEnabled = $true })
$cb_installjcagent.Add_Checked( { $img_ckey_info.Visibility = 'Visible' })
$cb_installjcagent.Add_Checked( { $img_ckey_valid.Visibility = 'Visible' })
$cb_installjcagent.Add_Checked( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Password) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Password)) -eq $false) {
            #$tbJumpCloudConnectKey.Tooltip = "Connect Key Must be 40chars & Not Contain Spaces"
            $tbJumpCloudConnectKey.Background = "#FFC6CBCF"
            $tbJumpCloudConnectKey.BorderBrush = "#FFF90000"
        } Else {
            $tbJumpCloudConnectKey.Background = "white"
            $tbJumpCloudConnectKey.Tooltip = $null
            $tbJumpCloudConnectKey.FontWeight = "Normal"
            $tbJumpCloudConnectKey.BorderBrush = "#FFC6CBCF"
        }

    })

$cb_installjcagent.Add_UnChecked( { Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey) })
$cb_installjcagent.Add_Unchecked( { $script:InstallJCAgent = $false })
$cb_installjcagent.Add_Unchecked( { $tbJumpCloudConnectKey.IsEnabled = $false })
$cb_installjcagent.Add_Unchecked( { $img_ckey_info.Visibility = 'Hidden' })
$cb_installjcagent.Add_Unchecked( { $img_ckey_valid.Visibility = 'Hidden' })
$cb_installjcagent.Add_Unchecked( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Password) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Password) -or ($cb_installjcagent.IsEnabled)) -eq $false) {
            #$tbJumpCloudConnectKey.Tooltip = "Connect Key Must be 40chars & Not Contain Spaces"
            $tbJumpCloudConnectKey.Background = "#FFC6CBCF"
            $tbJumpCloudConnectKey.BorderBrush = "#FFF90000"
        } Else {
            $tbJumpCloudConnectKey.Background = "white"
            $tbJumpCloudConnectKey.Tooltip = $null
            $tbJumpCloudConnectKey.FontWeight = "Normal"
            $tbJumpCloudConnectKey.BorderBrush = "#FFC6CBCF"
        }
    })


# Autobind JC User checkbox
$script:AutobindJCUser = $false
$cb_autobindjcuser.Add_Checked( { Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey) })
$cb_autobindjcuser.Add_Checked( { $script:AutobindJCUser = $true })
$cb_autobindjcuser.Add_Checked( { $tbJumpCloudAPIKey.IsEnabled = $true })
$cb_autobindjcuser.Add_Checked( { $img_apikey_info.Visibility = 'Visible' })
$cb_autobindjcuser.Add_Checked( { $img_apikey_valid.Visibility = 'Visible' })
$cb_autobindjcuser.Add_Checked( { $cb_bindAsAdmin.IsEnabled = $true })
$cb_bindAsAdmin.Add_Checked( { $script:BindAsAdmin = $true })
$cb_autobindjcuser.Add_Checked( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (Test-IsNotEmpty $tbJumpCloudAPIKey.Password ) {
            #$tbJumpCloudAPIKey.Tooltip = "API Key Must be 40chars & Not Contain Spaces"
            $tbJumpCloudAPIKey.Background = "#FFC6CBCF"
            $tbJumpCloudAPIKey.BorderBrush = "#FFF90000"
        } Else {
            $tbJumpCloudAPIKey.Background = "white"
            $tbJumpCloudAPIKey.Tooltip = $null
            $tbJumpCloudAPIKey.FontWeight = "Normal"
            $tbJumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
        }
    })


$cb_autobindjcuser.Add_UnChecked( { Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey) })
$cb_autobindjcuser.Add_Unchecked( { $script:AutobindJCUser = $false })
$cb_autobindjcuser.Add_Unchecked( { $tbJumpCloudAPIKey.IsEnabled = $false })
$cb_autobindjcuser.Add_Unchecked( { $img_apikey_info.Visibility = 'Hidden' })
$cb_autobindjcuser.Add_Unchecked( { $img_apikey_valid.Visibility = 'Hidden' })
$cb_autobindjcuser.Add_Unchecked( { $cb_bindAsAdmin.IsEnabled = $false })
$cb_autobindjcuser.Add_Unchecked( { $cb_bindAsAdmin.IsChecked = $false })
$cb_bindAsAdmin.Add_Unchecked( { $script:BindAsAdmin = $false })
$cb_autobindjcuser.Add_Unchecked( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If ((!(Test-IsNotEmpty $tbJumpCloudAPIKey.Password) -or ($cb_autobindjcuser.IsEnabled)) -eq $false) {
            #$tbJumpCloudAPIKey.Tooltip = "API Key Must be 40chars & Not Contain Spaces"
            $tbJumpCloudAPIKey.Background = "#FFC6CBCF"
            $tbJumpCloudAPIKey.BorderBrush = "#FFF90000"
        } Else {
            $tbJumpCloudAPIKey.Background = "white"
            $tbJumpCloudAPIKey.Tooltip = $null
            $tbJumpCloudAPIKey.FontWeight = "Normal"
            $tbJumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
        }
    })


# Leave Domain checkbox
if (($AzureADStatus -eq 'Yes') -or ($AzureDomainStatus -eq 'Yes')) {
    $script:cb_leavedomain.IsEnabled = $true
} else {
    Write-ToLog "Device is not AzureAD Joined or Domain Joined. Leave Domain Checkbox Disabled."
    $script:cb_leavedomain.IsEnabled = $false
}
$script:LeaveDomain = $false
$cb_leavedomain.Add_Checked( { $script:LeaveDomain = $true })
$cb_leavedomain.Add_Unchecked( { $script:LeaveDomain = $false })

# Force Reboot checkbox
$script:ForceReboot = $false
$cb_forcereboot.Add_Checked( { $script:ForceReboot = $true })
$cb_forcereboot.Add_Unchecked( { $script:ForceReboot = $false })

$hostname = $env:computername
$tbJumpCloudUserName.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If ((Test-IsNotEmpty $tbJumpCloudUserName.Text) -or (!(Test-HasNoSpace $tbJumpCloudUserName.Text)) -or (Test-Localusername $tbJumpCloudUserName.Text) -or (($tbJumpCloudUserName.Text).Length -gt 20) -or $tbJumpCloudUserName.Text -eq $hostname) {
            $tbJumpCloudUserName.Background = "#FFC6CBCF"
            $tbJumpCloudUserName.BorderBrush = "#FFF90000"
            $img_localaccount_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
            $img_localaccount_valid.ToolTip = "Local account username can't be empty, contain spaces, already exist on the local system or match the local computer name. Username must only be 20 characters long"
        } Else {
            $tbJumpCloudUserName.Background = "white"
            $tbJumpCloudUserName.FontWeight = "Normal"
            $tbJumpCloudUserName.BorderBrush = "#FFC6CBCF"
            $img_localaccount_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
            $img_localaccount_valid.ToolTip = $null
        }
        if ($tbJumpCloudUserName.Text -eq $hostname) {
            Write-ToLog "JumpCloud Username can not be the same as the hostname"
            $script:bMigrateProfile.IsEnabled = $false
            $img_localaccount_valid.ToolTip = "JumpCloud Username can not be the same as the hostname. Please change the username."
        }
    })

$tbJumpCloudConnectKey.Add_PasswordChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Password) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Password)) -eq $false) {
            $tbJumpCloudConnectKey.Background = "#FFC6CBCF"
            $tbJumpCloudConnectKey.BorderBrush = "#FFF90000"
            $img_ckey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
            $img_ckey_valid.ToolTip = "Connect Key must be 40chars & not contain spaces."
        } Else {
            $tbJumpCloudConnectKey.Background = "white"
            $tbJumpCloudConnectKey.FontWeight = "Normal"
            $tbJumpCloudConnectKey.BorderBrush = "#FFC6CBCF"
            $img_ckey_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
            $img_ckey_valid.ToolTip = $null
        }
    })

$tbJumpCloudAPIKey.Add_PasswordChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (Test-IsNotEmpty $tbJumpCloudAPIKey.Password) {
            $tbJumpCloudAPIKey.Background = "#FFC6CBCF"
            $tbJumpCloudAPIKey.BorderBrush = "#FFF90000"
            $img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
            $img_apikey_valid.ToolTip = "Please enter a valid JumpCloud API Key"

        } Else {
            # Get org name/ id
            try {
                $OrgSelection = Get-mtpOrganization -ApiKey $tbJumpCloudAPIKey.Password -inputType #-errorAction silentlycontinue
                $lbl_orgName.Text = "$($OrgSelection[1])"
                $Env:selectedOrgID = "$($OrgSelection[0])"
                $tbJumpCloudAPIKey.Background = "white"
                $tbJumpCloudAPIKey.Tooltip = $null
                $tbJumpCloudAPIKey.FontWeight = "Normal"
                $tbJumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
                $img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
                $img_apikey_valid.ToolTip = $null
                Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
            } catch {
                $script:bMigrateProfile.IsEnabled = $false
                $img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
                $img_apikey_valid.ToolTip = "Please enter a valid JumpCloud API Key"
                $OrgSelection = ""
                $lbl_orgName.Text = ""
                $img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
                Write-ToLog "MTP KEY MAY BE WRONG"
            }
        }
    })
$tbTempPassword.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If ((!(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)) -eq $false) {
            $tbTempPassword.Background = "#FFC6CBCF"
            $tbTempPassword.BorderBrush = "#FFF90000"
            $img_localaccount_password_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
            $img_localaccount_password_valid.ToolTip = "Local Account Temp Password should not be empty or contain spaces, it should also meet local password policy req. on the system."
        } Else {
            $tbTempPassword.Background = "white"
            $tbTempPassword.Tooltip = $null
            $tbTempPassword.FontWeight = "Normal"
            $tbTempPassword.BorderBrush = "#FFC6CBCF"
            $img_localaccount_password_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
            $img_localaccount_password_valid.ToolTip = $null
        }
    })

# Change button when profile selected
$lvProfileList.Add_SelectionChanged( {
        $script:SelectedUserName = ($lvProfileList.SelectedItem.username)
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        try {
            $SelectedUserSID = ((New-Object System.Security.Principal.NTAccount($script:SelectedUserName)).Translate( [System.Security.Principal.SecurityIdentifier]).Value)
        } catch {
            $SelectedUserSID = $script:SelectedUserName
        }
        $hku = ('HKU:\' + $SelectedUserSID)
        if (Test-Path -Path $hku) {
            $script:bMigrateProfile.IsEnabled = $false
            $script:tbJumpCloudUserName.IsEnabled = $false
            $script:tbTempPassword.IsEnabled = $false
        } else {
            $script:tbJumpCloudUserName.IsEnabled = $true
            $script:tbTempPassword.IsEnabled = $true
        }
    })

$bMigrateProfile.Add_Click( {
        if ($tbJumpCloudAPIKey.Password -And $tbJumpCloudUserName.Text -And $AutobindJCUser) {
            # If text field is default/ not 40 chars
            if (!(Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Password)) {
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

            $testResult, $JumpCloudUserId, $JCSystemUsername = Test-JumpCloudUsername -JumpCloudApiKey $tbJumpCloudAPIKey.Password -JumpCloudOrgID $Env:selectedOrgID -Username $tbJumpCloudUserName.Text -Prompt $true
            if ($testResult) {
                Write-ToLog "Matched $($tbJumpCloudUserName.Text) with user in the JumpCloud Console"
            } else {
                Write-ToLog "$($tbJumpCloudUserName.Text) not found in the JumpCloud console"
                return
            }
            if ( -not [string]::isnullorempty($JCSystemUsername) ) {
                # Regex to get the username from the domain\username string and compare it to JCSystemUsername
                #Get all the local users
                $registyProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                $profileList = @()
                foreach ($profile in $registyProfiles) {
                    $profileList += Get-ItemProperty -Path $profile.PSPath | Select-Object PSChildName, ProfileImagePath, @{ Name = "username"; Expression = { $sysUsername = Convert-Sid -sid $_.PSChildName; $sysUsername.Split('\')[1] } }
                }
                # If the JumpCloud found username was identified to exist locally, throw message
                if ($JCSystemUsername -in $profileList.username) {
                    # Create a pop up that warns user then press ok to continue
                    Write-ToLog "JCSystemUsername $($JCSystemUsername) is the same as the another profile on this system"
                    $wshell = New-Object -ComObject Wscript.Shell
                    $message = "The JumpCloud User: $($tbJumpCloudUserName.Text) has a local account username of: $($jcsystemUserName). A local account already exists on this system with username: $($JCSystemUsername), please consider removing either the local account on this system or removing the local user account field from the JumpCloud user."
                    $var = $wshell.Popup("$message", 0, "JumpCloud SystemUsername and Local Computer Username Validation", 0)
                    # the user can not continue with migration at this stage
                    return
                }
                $wshell = New-Object -ComObject Wscript.Shell
                $message = "The JumpCloud User: $($tbJumpCloudUserName.Text) has a local account username of: $($jcsystemUserName). After migration $($SelectedUserName) would be migrated and accessible with the local account username of: $($jcsystemUserName) Would you like to continue?"
                $var = $wshell.Popup("$message", 0, "JumpCloud Local User Validation", 64 + 4)
                # If user selects yes then migrate the local user profile to the JumpCloud User

                if ($var -eq 6) {
                    Write-ToLog -Message "User selected 'Yes', continuing with migration of $($SelectedUserName) to $($jcsystemUserName)"
                } else {
                    Write-ToLog -Message "User selected 'No', returning to form"
                    return
                }
            } else {
                Write-ToLog "User $($tbJumpCloudUserName.Text) does not have a local account on this system"
            }
        }
        # Build FormResults object
        Write-ToLog "Building Form Results"
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('InstallJCAgent') -Value:($InstallJCAgent)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('AutobindJCUser') -Value:($AutobindJCUser)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('BindAsAdmin') -Value:($BindAsAdmin)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('LeaveDomain') -Value:($LeaveDomain)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('ForceReboot') -Value:($ForceReboot)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('SelectedUserName') -Value:($SelectedUserName)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudUserName') -Value:($tbJumpCloudUserName.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('TempPassword') -Value:($tbTempPassword.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudConnectKey') -Value:($tbJumpCloudConnectKey.Password)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudAPIKey') -Value:($tbJumpCloudAPIKey.Password)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudOrgID') -Value:($Env:selectedOrgID)
        # Close form
        $Form.Close()
    })

$tbJumpCloudUserName.add_GotFocus( {
        $tbJumpCloudUserName.Text = ""
    })

$tbJumpCloudConnectKey.add_GotFocus( {
        $tbJumpCloudConnectKey.Password = ""
    })

$tbJumpCloudAPIKey.add_GotFocus( {
        $tbJumpCloudAPIKey.Password = ""
    })

# lbl_connectkey link - Mouse button event
$lbl_connectkey.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://console.jumpcloud.com/#/systems/new') })

# lbl_apikey link - Mouse button event
$lbl_apikey.Add_PreviewMouseDown( { [System.Diagnostics.Process]::start('https://support.jumpcloud.com/support/s/article/jumpcloud-apis1') })

# move window
$Form.Add_MouseLeftButtonDown( {
        $Form.DragMove()
    })
$Form.Add_Closing({
        # exit and close form
        $FormResults = $null
        Return $FormResults
    })
# Put the list of profiles in the profile box
$Profiles | ForEach-Object { $lvProfileList.Items.Add($_) | Out-Null }
#===========================================================================
# Shows the form & allow move
#===========================================================================

$Form.Showdialog()

If ($bMigrateProfile.IsEnabled -eq $true) {
    Return $FormResults
}