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
                $dynamicLabel.Text = "OrgName: $($combobox.SelectedItem['Text'])`nOrgID: $($combobox.SelectedItem['Value'])"
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
        Title="JumpCloud ADMU 2.1.3"
        WindowStyle="SingleBorderWindow"
        ResizeMode="NoResize"
        Background="White" ScrollViewer.VerticalScrollBarVisibility="Visible" ScrollViewer.HorizontalScrollBarVisibility="Visible" Width="1000" Height="520">

    <Grid Margin="0,0,0,0">
        <Grid.RowDefinitions>
            <RowDefinition/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="118*"/>
            <ColumnDefinition Width="57*"/>
            <ColumnDefinition Width="23*"/>
        </Grid.ColumnDefinitions>
        <ListView Name="lvProfileList" MinWidth="960" MinHeight="120" Width="960" MaxWidth="960" MaxHeight="120" Height="110" Margin="10,187,0,0" HorizontalAlignment="Left" VerticalAlignment="Top" Grid.ColumnSpan="3">
            <ListView.View>
                <GridView>
                    <GridViewColumn Header="System Accounts" DisplayMemberBinding="{Binding UserName}" Width="300"/>
                    <GridViewColumn Header="Last Login" DisplayMemberBinding="{Binding LastLogin}" Width="135"/>
                    <GridViewColumn Header="Currently Active" DisplayMemberBinding="{Binding Loaded}" Width="145" />
                    <GridViewColumn Header="Local Admin" DisplayMemberBinding="{Binding IsLocalAdmin}" Width="115"/>
                    <GridViewColumn Header="Local Path" DisplayMemberBinding="{Binding LocalPath}" Width="225"/>
                </GridView>
            </ListView.View>
        </ListView>
        <GroupBox Header="System Migration Options" Width="480" FontWeight="Bold" HorizontalAlignment="Left" MinWidth="480" MinHeight="165" Margin="10,306,0,0" VerticalAlignment="Top" Height="168">
            <Grid HorizontalAlignment="Left" Height="141" VerticalAlignment="Top" Width="470">
                <TextBlock Name="lbl_connectkey" HorizontalAlignment="Left" Margin="3,13,0,0" Text="JumpCloud Connect Key :" VerticalAlignment="Top" TextDecorations="Underline" Foreground="#FF000CFF"/>
                <TextBox Name="tbJumpCloudConnectKey" HorizontalAlignment="Left" Height="23" Margin="178,10,0,0" Text="Enter JumpCloud Connect Key" VerticalAlignment="Top" Width="271" Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False"/>
                <TextBlock Name="lbl_apikey" HorizontalAlignment="Left" Margin="3,42,0,0" Text="JumpCloud API Key :" VerticalAlignment="Top" TextDecorations="Underline" Foreground="#FF000CFF"/>
                <TextBox Name="tbJumpCloudAPIKey" HorizontalAlignment="Left" Height="23" Margin="178,40,0,0" Text="Enter JumpCloud API Key" VerticalAlignment="Top" Width="271" Background="#FFC6CBCF" FontWeight="Bold" IsEnabled="False"/>
                <TextBlock Name="lbl_orgNameTitle" HorizontalAlignment="Left" Margin="3,64,0,0" Text="Organization Name:" VerticalAlignment="Top" FontWeight="Normal"/>
                <TextBlock Name="lbl_orgName" HorizontalAlignment="Left" Margin="118,64,0,0" Text="Not Currently Connected To A JumpCloud Organization" VerticalAlignment="Top" FontWeight="Normal"/>
                <TextBlock Name="lbl_orgidTitle" HorizontalAlignment="Left" Margin="3,79,0,0" Text="Organization ID:" VerticalAlignment="Top" FontWeight="Normal"/>
                <TextBlock Name="lbl_orgid" HorizontalAlignment="Left" Margin="96,79,0,0" Text="" VerticalAlignment="Top" FontWeight="Normal"/>
                <CheckBox Name="cb_forcereboot" Content="Force Reboot" HorizontalAlignment="Left" Margin="10,101,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_installjcagent" Content="Install JCAgent" HorizontalAlignment="Left" Margin="123,101,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_bindAsAdmin" Content="Bind As Admin" HorizontalAlignment="Left" Margin="253,101,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False" IsEnabled="False"/>
                <CheckBox Name="cb_leavedomain" ToolTipService.ShowOnDisabled="True" Content="Leave Domain" HorizontalAlignment="Left" Margin="10,123,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <CheckBox Name="cb_autobindjcuser" Content="Autobind JC User" HorizontalAlignment="Left" Margin="123,123,0,0" VerticalAlignment="Top" FontWeight="Normal" IsChecked="False"/>
                <Image Name="img_ckey_info" HorizontalAlignment="Left" Height="14" Margin="157,13,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="The Connect Key provides you with a means of associating this system with your JumpCloud organization. The Key is used to deploy the agent to this system." />
                <Image Name="img_ckey_valid" HorizontalAlignment="Left" Height="14" Margin="454,13,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Connect Key must be 40chars &amp; not contain spaces" />
                <Image Name="img_apikey_info" HorizontalAlignment="Left" Height="14" Margin="157,42,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Click the link for more info on how to obtain the api key. The API key must be from a user with at least 'Manager' or 'Administrator' privileges." RenderTransformOrigin="1.857,-1.066"/>
                <Image Name="img_apikey_valid" HorizontalAlignment="Left" Height="14" Margin="454,42,0,0" VerticalAlignment="Top" Width="14" Visibility="Hidden" ToolTip="Correct error" />
            </Grid>
        </GroupBox>
        <GroupBox Header="Account Migration Information" FontWeight="Bold" Height="107" Width="475" Margin="495,306,0,0" HorizontalAlignment="Left" VerticalAlignment="Top" Grid.ColumnSpan="3">
            <Grid HorizontalAlignment="Left" Height="66" VerticalAlignment="Top" Width="461">
                <Label Content="Local Account Username :" HorizontalAlignment="Left" Margin="0,8,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.ColumnSpan="2"/>
                <Label Content="Local Account Password :" HorizontalAlignment="Left" Margin="0,36,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.ColumnSpan="2"/>
                <TextBox Name="tbJumpCloudUserName" HorizontalAlignment="Left" Height="23" Margin="192,10,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="235" Text="Username should match JumpCloud username" Background="#FFC6CBCF" FontWeight="Bold" />
                <TextBox Name="tbTempPassword" HorizontalAlignment="Left" Height="23" Margin="192,38,0,0" TextWrapping="Wrap" Text="Temp123!Temp123!" VerticalAlignment="Top" Width="235" FontWeight="Normal"/>
                <Image Name="img_localaccount_info" HorizontalAlignment="Left" Height="14" Margin="169,12,0,0" VerticalAlignment="Top" Width="14" Visibility="Visible" ToolTip="The value in this field should match a username in the jc console. A new local user account will be created with this username." />
                <Image Name="img_localaccount_valid" HorizontalAlignment="Left" Height="14" Margin="432,12,0,0" VerticalAlignment="Top" Width="14" ToolTip="Local account username can't be empty, contain spaces, already exist on the local system or match the local computer name." Visibility="Visible" />
                <Image Name="img_localaccount_password_info" HorizontalAlignment="Left" Height="14" Margin="169,42,0,0" VerticalAlignment="Top" Width="14" Visibility="Visible" ToolTip="This temporary password is used on account creation. The password will be ovewritten by the users jc password if autobound or manually bound in the console."/>
                <Image Name="img_localaccount_password_valid" HorizontalAlignment="Left" Height="14" Margin="432,40,0,0" VerticalAlignment="Top" Width="14" Visibility="Visible"/>
            </Grid>
        </GroupBox>
        <GroupBox Header="System Information" FontWeight="Bold" Width="303" Height="148" MaxHeight="160" Margin="10,34,0,0" HorizontalAlignment="Left" VerticalAlignment="Top">
            <Grid HorizontalAlignment="Left" Height="125" Margin="10,0,0,0" VerticalAlignment="Center" Width="245" MinWidth="245" MinHeight="125">
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
                <Label Content="AzureAD Joined:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="3" />
                <Label Content="Tenant Name:" HorizontalAlignment="Left" Margin="0,0,0,0" VerticalAlignment="Top" FontWeight="Normal" Grid.Column="0" Grid.ColumnSpan="1" Grid.Row="4"/>
                <Label Name="lbTenantName" Content="" FontWeight="Normal" Grid.Column="3" Grid.Row="4"/>
                <Label Name="lbAzureAD_Joined" Content="" FontWeight="Normal" Grid.Column="1" Grid.Row="3"/>
                <Label Name="lbComputerName" Content="" FontWeight="Normal" Grid.Column="1" Grid.Row="0"/>
                <Label Name="lbDomainName" Content="" FontWeight="Normal" Grid.Column="1" Grid.Row="1"/>
                <Label Name="lbNetBios" Content="" FontWeight="Normal" Grid.Column="1" Grid.Row="2"/>
            </Grid>
        </GroupBox>
        <Image Name="JCLogoImg" HorizontalAlignment="Left" Height="33" VerticalAlignment="Top" Margin="9,0,0,0" Width="500"/>
        <Button Name="bMigrateProfile" Content="Select Profile" HorizontalAlignment="Left" Margin="237,418,0,0" VerticalAlignment="Top" Width="146" Height="26" IsEnabled="False" Grid.Column="1" Grid.ColumnSpan="2"/>
        <GroupBox Header="Migration Steps" HorizontalAlignment="Left" Height="148" VerticalAlignment="Top" Width="655" FontWeight="Bold" Margin="315,34,0,0" Grid.ColumnSpan="3">
            <TextBlock HorizontalAlignment="Center" TextWrapping="Wrap" VerticalAlignment="Top" Height="118" Width="632" FontWeight="Normal"><Run Text="1. Select a domain or AzureAD account to be migrated to a local account from the list below."/><LineBreak/><Run Text="2. Enter a local account username and temporary password. The selected account will be migrated to this local account."/><LineBreak/><Run Text="3.(Optionally) Select Install JC Agent and provide a Connect Key to install the JC agent on this system."/><LineBreak/><Run Text="4.(Optionally) Select Autobind JC User and provide an API Key to bind the new local username to your JC organization."/><LineBreak/><Run Text="5.(Optionally) Select Force Reboot and/or Leave Domain as required."/><LineBreak/><Run Text="6. Click the Migrate Profile button."/><LineBreak/><Run Text="For further information check out the JC ADMU Wiki. - https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki"/></TextBlock>
        </GroupBox>
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
        If (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) `
                -and ((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text) -and ($cb_installjcagent.IsChecked -eq $true))`
                -and ((Test-CharLen -len 40 -testString $tbJumpCloudAPIKey.Text) -and (Test-HasNoSpace $tbJumpCloudAPIKey.Text) -and ($cb_autobindjcuser.IsChecked -eq $true))`
                -and ((Test-CharLen -len 24 -testString $lbl_orgId.Text) -and (Test-HasNoSpace $lbl_orgId.Text) -and ($cb_autobindjcuser.IsChecked -eq $true))`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(($($lvProfileList.selectedItem.Username) -split '\\')[0] -match $WmiComputerSystem.Name)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } ElseIf (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) `
                -and ((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text) -and ($cb_installjcagent.IsChecked -eq $true) -and ($cb_autobindjcuser.IsChecked -eq $false))`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } ElseIf (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) `
                -and ((Test-CharLen -len 40 -testString $tbJumpCloudAPIKey.Text) -and (Test-HasNoSpace $tbJumpCloudAPIKey.Text) -and ($cb_autobindjcuser.IsChecked -eq $true) -and ($cb_installjcagent.IsChecked -eq $false))`
                -and ((Test-CharLen -len 24 -testString $lbl_orgId.Text) -and (Test-HasNoSpace $lbl_orgId.Text) -and ($cb_autobindjcuser.IsChecked -eq $true) -and ($cb_installjcagent.IsChecked -eq $false))`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } Elseif (!(Test-IsNotEmpty $tbJumpCloudUserName.Text) -and (Test-HasNoSpace $tbJumpCloudUserName.Text) `
                -and ($cb_installjcagent.IsChecked -eq $false) -and ($cb_autobindjcuser.IsChecked -eq $false)`
                -and !(Test-IsNotEmpty $tbTempPassword.Text) -and (Test-HasNoSpace $tbTempPassword.Text)`
                -and !($lvProfileList.selectedItem.Username -match $WmiComputerSystem.Name)`
                -and !(Test-Localusername $tbJumpCloudUserName.Text)) {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $true
            Return $true
        } Elseif ($lvProfileList.selectedItem.Username -eq 'UNKNOWN ACCOUNT') {
            # Unmatched Profile, prevent migration
            $script:bMigrateProfile.Content = "Select Domain Profile"
            $script:bMigrateProfile.IsEnabled = $false
            Return $false
        } elseif (($($lvProfileList.selectedItem.Username) -split '\\')[0] -match $WmiComputerSystem.Name) {
            $script:bMigrateProfile.Content = "Select Domain Profile"
            $script:bMigrateProfile.IsEnabled = $false
            Return $false
        } Else {
            $script:bMigrateProfile.Content = "Migrate Profile"
            $script:bMigrateProfile.IsEnabled = $false
            Return $false
        }
    } Else {
        $script:bMigrateProfile.Content = "Select Profile"
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
        If (((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text)) -eq $false) {
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
        If (((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text) -or ($cb_installjcagent.IsEnabled)) -eq $false) {
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
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbJumpCloudConnectAPIKey:($tbJumpCloudAPIKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (((Test-CharLen -len 40 -testString $tbJumpCloudAPIKey.Text) -and (Test-HasNoSpace $tbJumpCloudAPIKey.Text)) -eq $false) {
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
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbJumpCloudConnectAPIKey:($tbJumpCloudAPIKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (((Test-CharLen -len 40 -testString $tbJumpCloudAPIKey.Text) -and (Test-HasNoSpace $tbJumpCloudAPIKey.Text) -or ($cb_autobindjcuser.IsEnabled)) -eq $false) {
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
# If system is joined to AzureAD, disable Leave Domain checkbox
if ($AzureADStatus -eq "YES") {
    $cb_leavedomain.ToolTip = "Unable to automatically leave domain due to being AzureAD Joined and running as local administrator - https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Leaving-AzureAD-Domains"
    $cb_leavedomain.Add_Unchecked( { $script:LeaveDomain = $false })
    $cb_leavedomain.IsEnabled = $false
} else {
    $script:LeaveDomain = $false
    $cb_leavedomain.Add_Checked( { $script:LeaveDomain = $true })
    $cb_leavedomain.Add_Unchecked( { $script:LeaveDomain = $false })
}

# Force Reboot checkbox
$script:ForceReboot = $false
$cb_forcereboot.Add_Checked( { $script:ForceReboot = $true })
$cb_forcereboot.Add_Unchecked( { $script:ForceReboot = $false })

$tbJumpCloudUserName.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If ((Test-IsNotEmpty $tbJumpCloudUserName.Text) -or (!(Test-HasNoSpace $tbJumpCloudUserName.Text)) -or (Test-Localusername $tbJumpCloudUserName.Text)) {
            $tbJumpCloudUserName.Background = "#FFC6CBCF"
            $tbJumpCloudUserName.BorderBrush = "#FFF90000"
            $img_localaccount_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
            $img_localaccount_valid.ToolTip = "Local account username can't be empty, contain spaces, already exist on the local system or match the local computer name."
        } Else {
            $tbJumpCloudUserName.Background = "white"
            $tbJumpCloudUserName.FontWeight = "Normal"
            $tbJumpCloudUserName.BorderBrush = "#FFC6CBCF"
            $img_localaccount_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
            $img_localaccount_valid.ToolTip = $null
        }
    })

$tbJumpCloudConnectKey.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)
        If (((Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Text) -and (Test-HasNoSpace $tbJumpCloudConnectKey.Text)) -eq $false) {
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

$tbJumpCloudAPIKey.add_TextChanged( {
        Test-Button -tbJumpCloudUserName:($tbJumpCloudUserName) -tbJumpCloudConnectKey:($tbJumpCloudConnectKey) -tbJumpCloudConnectAPIKey:($tbJumpCloudAPIKey) -tbTempPassword:($tbTempPassword) -lvProfileList:($lvProfileList) -tbJumpCloudAPIKey:($tbJumpCloudAPIKey)

        If (((Test-CharLen -len 40 -testString $tbJumpCloudAPIKey.Text) -and (Test-HasNoSpace $tbJumpCloudAPIKey.Text)) -eq $false) {
            $tbJumpCloudAPIKey.Background = "#FFC6CBCF"
            $tbJumpCloudAPIKey.BorderBrush = "#FFF90000"
            $img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ErrorBase64
            $img_apikey_valid.ToolTip = "Jumpcloud API Key must be 40chars & not contain spaces."

        } Else {
            # Get org name/ id
            try {
                $OrgSelection = Get-mtpOrganization -ApiKey $tbJumpCloudAPIKey.Text -inputType #-errorAction silentlycontinue
                $lbl_orgName.Text = "$($OrgSelection[1])"
                $lbl_orgId.Text = "$($OrgSelection[0])"
                $tbJumpCloudAPIKey.Background = "white"
                $tbJumpCloudAPIKey.Tooltip = $null
                $tbJumpCloudAPIKey.FontWeight = "Normal"
                $tbJumpCloudAPIKey.BorderBrush = "#FFC6CBCF"
                $img_apikey_valid.Source = DecodeBase64Image -ImageBase64 $ActiveBase64
                $img_apikey_valid.ToolTip = $null
            } catch {
                $OrgSelection = ""
                $lbl_orgName.Text = ""
                $lbl_orgId.Text = ""
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
            $script:bMigrateProfile.Content = "User Registry Loaded"
            $script:bMigrateProfile.IsEnabled = $false
            $script:tbJumpCloudUserName.IsEnabled = $false
            $script:tbTempPassword.IsEnabled = $false
        } else {
            $script:tbJumpCloudUserName.IsEnabled = $true
            $script:tbTempPassword.IsEnabled = $true
        }
    })

$bMigrateProfile.Add_Click( {
        if ($tbJumpCloudAPIKey.Text -And $tbJumpCloudUserName.Text -And $AutobindJCUser) {
            # If text field is default/ not 40 chars
            if (!(Test-CharLen -len 40 -testString $tbJumpCloudConnectKey.Text)) {
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
            $testResult, $userID = Test-JumpCloudUsername -JumpCloudApiKey $tbJumpCloudAPIKey.Text -JumpCloudOrgID $lbl_orgId.Text -Username $tbJumpCloudUserName.Text -Prompt $true
            if ($testResult) {
                Write-ToLog "Matched $($tbJumpCloudUserName.Text) with user in the JumpCloud Console"
            } else {
                Write-ToLog "$($tbJumpCloudUserName.Text) not found in the JumpCloud console"
                return
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
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudConnectKey') -Value:($tbJumpCloudConnectKey.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudAPIKey') -Value:($tbJumpCloudAPIKey.Text)
        Add-Member -InputObject:($FormResults) -MemberType:('NoteProperty') -Name:('JumpCloudOrgID') -Value:($lbl_orgId.Text)
        # Close form
        $Form.Close()
    })

$tbJumpCloudUserName.add_GotFocus( {
        $tbJumpCloudUserName.Text = ""
    })

$tbJumpCloudConnectKey.add_GotFocus( {
        $tbJumpCloudConnectKey.Text = ""
    })

$tbJumpCloudAPIKey.add_GotFocus( {
        $tbJumpCloudAPIKey.Text = ""
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