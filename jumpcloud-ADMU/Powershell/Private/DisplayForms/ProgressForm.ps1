function New-ProgressForm {
    # syncHash the values
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework') | Out-Null
    $syncHash = [hashtable]::Synchronized(@{ })
    $newRunspace = [runspacefactory]::CreateRunspace()
    $syncHash.Runspace = $newRunspace
    $syncHash.PercentComplete = $PercentComplete
    $syncHash.StatusInput = ''
    $syncHash.LogText = @()
    $syncHash.logLevel = ''
    $syncHash.base64JCLogo = Get-ImageFromB64 -ImageBase64 $JCLogoBase64
    $syncHash.closeWindow = $false

    # Migration Details
    $syncHash.UsernameInput = ''
    $syncHash.ProfileSizeInput = ''
    $syncHash.LocalPathInput = ''
    $syncHash.NewLocalUsernameInput = ''

    $syncHash.XAML = @"
    <Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Name="Window" Title="JumpCloud ADMU 2.9.3"
    WindowStyle="SingleBorderWindow"
    ResizeMode="NoResize"
    Background="White" Width="720" Height="550  ">
    <Window.Resources>
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
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="Normal"/>
            <Setter Property="Foreground" Value="#202D38"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="FontFamily" Value="Segoe UI"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Foreground" Value="#202D38"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
        </Style>
        <Style TargetType="ProgressBar">
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ProgressBar">
                        <Grid>
                            <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="4">
                                <Grid x:Name="PART_Track" ClipToBounds="True" Background="Transparent">
                                    <Border x:Name="PART_Indicator" Background="{TemplateBinding Foreground}" HorizontalAlignment="Left" CornerRadius="4"/>
                                </Grid>
                            </Border>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid>
        <Image Name="JCLogoImg" Source="C:\Users\kmara\Downloads\JC oceanblue tm.png" Margin="10,10,0,0" HorizontalAlignment="Left" Height="23" VerticalAlignment="Top"/>


        <Grid Margin="10,0,10,0" >
            <Grid.RowDefinitions>
                <RowDefinition Height="auto" MinHeight="216"/>
                <RowDefinition Height="auto" MinHeight="94"/>
                <RowDefinition Height="Auto" MinHeight="130"/>
                <RowDefinition Height="Auto"/>
            </Grid.RowDefinitions>
            <GroupBox Header="" Style="{StaticResource NoHeaderGroupBoxStyle}" FontWeight="Bold" Width="auto" MaxHeight="160" Margin="0,46,0,10" HorizontalAlignment="Left">
                <Grid HorizontalAlignment="Left" Height="auto" Margin="10,0,0,0" VerticalAlignment="Center" Width="auto" MinWidth="245" MinHeight="100" Grid.Row="0">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="118"/>
                        <ColumnDefinition Width="auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock Text="Migration Details" FontWeight="SemiBold" Grid.Row="0" Margin="0,0,0,10" FontSize="12"/>
                    <Label Content="Username: " HorizontalAlignment="Left" VerticalAlignment="Center" FontWeight="Normal" Grid.Row="1" Height="25" Width="69" />
                    <Label Content="ProfileSize: " HorizontalAlignment="Left" VerticalAlignment="Center" FontWeight="Normal" Grid.Row="2" Height="25" Width="71" />
                    <Label Content="LocalPath:" HorizontalAlignment="Left" VerticalAlignment="Center" FontWeight="Normal" Grid.Row="3" Height="25" Width="63" />
                    <Label Content="NewLocalUsername:" HorizontalAlignment="Left" VerticalAlignment="Center" FontWeight="Normal" Grid.Row="4" Height="25" Width="118" />
                    <Label Name="Username" Content="..." FontWeight="SemiBold" Grid.Row="1" Grid.Column="1" VerticalAlignment="Center" HorizontalAlignment="Right" Margin="22,0,0,0" />
                    <Label Name="ProfileSize" Content="0.8GB" FontWeight="SemiBold" Grid.Row="2" Grid.Column="1" Margin="22,0,0,0" HorizontalAlignment="Right"/>
                    <Label Name="LocalPath" Content="..." FontWeight="SemiBold" Grid.Row="3" Grid.Column="1" Margin="22,0,0,0" HorizontalAlignment="Right"/>
                    <Label Name="NewLocalUsername" Content="..." FontWeight="SemiBold" Grid.Row="4" Grid.Column="1" Margin="22,0,0,0" HorizontalAlignment="Right"/>
                </Grid>
            </GroupBox>
            <GroupBox Header="" Style="{StaticResource NoHeaderGroupBoxStyle}" FontWeight="Bold" Height="94" Grid.Row="1">
                <StackPanel Height="86" VerticalAlignment="Center">
                    <TextBlock Text="Migration Status" FontWeight="SemiBold" FontSize="12" Margin="5,10,0,0"/>
                    <TextBlock Name="Status" TextWrapping="Wrap" Text="Status:" LineHeight="15" Width="auto"  FontSize="12" Height="auto" Margin="5,0,5,5" HorizontalAlignment="Left" FontWeight="Normal"/>
                    <TextBlock Name="ErrorBlock" Width="auto" FontSize="12" Height="auto" Margin="5,0,0,0" HorizontalAlignment="Left" FontWeight="Normal" Visibility="Collapsed">
            <Hyperlink Name="ErrorLink" NavigateUri="https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors">
                https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/troubleshooting-errors
            </Hyperlink>
                    </TextBlock>
                    <ProgressBar Name="ProgressBar" Height="8"  Foreground="#41C8c3" VerticalAlignment="Top" Width="645" Margin="5,0,0,20" Value="50" HorizontalAlignment="Left" Visibility="Visible" >
                    </ProgressBar>
                </StackPanel>
            </GroupBox>

            <StackPanel VerticalAlignment="Center" Grid.Row="2" >
                <Expander Header="View Log" Background="White" Foreground="#4373C7" Height="142" Margin="0,10,0,0">
                    <Expander.Resources>
                        <Style TargetType="{x:Type Border}">
                            <Setter Property="CornerRadius" Value="5"/>
                        </Style>
                    </Expander.Resources>
                    <Border BorderBrush="#E3E8E9" BorderThickness="1" CornerRadius="5" >
                        <ScrollViewer Name="ScrollLog" Foreground="Gray" HorizontalScrollBarVisibility="Disabled" VerticalAlignment="Center" Height="98" Width="650">
                            <TextBlock Name="LogTextBlock" TextWrapping="Wrap" FontWeight="Medium" FontSize="11">...</TextBlock>
                        </ScrollViewer>
                    </Border>
                </Expander>
            </StackPanel>

            <Grid Grid.Row="4" Margin="0,10,0,0" HorizontalAlignment="Right" VerticalAlignment="Top" Height="26" >

                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="0"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="0"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <Button Grid.Column="0" Name="ViewLogButton" Content="View Log" Height="26" Width="70"  IsEnabled="False"  Margin="0,0,10,0" HorizontalAlignment="Center">
                    <Button.Resources>
                        <Style TargetType="{x:Type Border}">
                            <Setter Property="CornerRadius" Value="3"/>
                        </Style>
                    </Button.Resources>
                </Button>
                <Button Grid.Column="2" Name="StartJCADMUButton" Content="Rerun"  Height="26" Width="70" IsEnabled="False" Margin="0,0,10,0">
                    <Button.Resources>
                        <Style TargetType="{x:Type Border}">
                            <Setter Property="CornerRadius" Value="3"/>
                        </Style>
                    </Button.Resources>
                </Button>
                <Button Grid.Column="4" Name="ExitButton" Content="Exit" Height="26" Width="70"  VerticalAlignment="Top" IsEnabled="False">
                    <Button.Resources>
                        <Style TargetType="{x:Type Border}">
                            <Setter Property="CornerRadius" Value="3"/>
                        </Style>
                    </Button.Resources>
                </Button>
            </Grid>
        </Grid>
    </Grid>
</Window>
"@
    # Colors
    # Foreground="#90b7fc" Darkblue
    # Foreground="#52C4C1" Teal
    # Create a runspace to run the form in
    $newRunspace.ApartmentState = "STA"
    $newRunspace.ThreadOptions = "ReuseThread"
    $data = $newRunspace.Open() | Out-Null
    $newRunspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

    # Add the form code to the powershell instance
    $psCommand = [PowerShell]::Create().AddScript({
            # Load an xaml form

            $syncHash.Window = [Windows.Markup.XamlReader]::parse( $SyncHash.XAML )
            ([xml]$SyncHash.XAML).SelectNodes("//*[@Name]") | ForEach-Object { $SyncHash."$($_.Name)" = $SyncHash.Window.FindName($_.Name) }
            # Image
            $SyncHash.JCLogoImg.Source = $syncHash.base64JCLogo
            $syncHash.Username.Content = $syncHash.UsernameInput
            $syncHash.ProfileSize.Content = $syncHash.ProfileSizeInput
            $syncHash.LocalPath.Content = $syncHash.LocalPathInput
            $syncHash.NewLocalUsername.Content = $syncHash.NewLocalUsernameInput

            # Scroll to end of Log
            $syncHash.ScrollLog.ScrollToEnd()


            $updateForm = {

                # Migration Details

                if ($SyncHash.closeWindow -eq $True) {
                    $syncHash.Window.Close()
                    [System.Windows.Forms.Application]::Exit()
                    Break
                }
                # IF close window button is clicked
                if ($SyncHash.Closing) {
                    $SyncHash.Window.Close()
                    [System.Windows.Forms.Application]::Exit()
                    Break
                }
                if ($SyncHash.logLevel -eq "Error") {
                    #$syncHash.Status.Foreground = "Red"
                    # Hide Progress Bar
                    $SyncHash.ProgressBar.Visibility = "Hidden"
                    # Show Error Link and make clickable
                    $syncHash.ErrorBlock.Visibility = "Visible"
                    # Clickable link
                    $SyncHash.ErrorLink.add_RequestNavigate({
                            #Sender is an event handler and used when the link is clicked https://learn.microsoft.com/en-us/dotnet/api/system.windows.navigation.requestnavigateeventargs.invokeeventhandler?view=windowsdesktop-8.0#system-windows-navigation-requestnavigateeventargs-invokeeventhandler(system-delegate-system-object
                            # Suppress PSScriptAnalyzer rule that warns about 'Sender' being an automatic variable
                            # <pragma>disable PSAvoidUsingAutomaticVariable
                            param ($SenderParam, $e)
                            if (-not $SenderParam) {
                                Write-Error "SenderParam needs to be populated"
                            }
                            [System.Diagnostics.Process]::Start($e.Uri.AbsoluteUri)  # Open the link in the default web browser
                            $e.Handled = $true
                        })

                }
                if ($syncHash.PercentComplete -eq 100) {
                    $SyncHash.ViewLogButton.IsEnabled = $true
                    $SyncHash.StartJCADMUButton.IsEnabled = $true
                    $SyncHash.ExitButton.IsEnabled = $true
                }

                # Update Log TextBlock
                $SyncHash.LogTextBlock.Text = $syncHash.LogText
                # Update Progress Bar
                $SyncHash.ProgressBar.Value = $SyncHash.PercentComplete
                # Update Status Text
                $SyncHash.Status.Text = $SyncHash.StatusInput

            }
            # View Log Button
            $SyncHash.ViewLogButton.Add_Click({
                    # Open log \Windows\Temp\jcAdmu.log
                    $scriptPath = "$(Get-WindowsDrive)\Windows\Temp\jcAdmu.log"
                    # Open the log
                    Invoke-Item -Path:($scriptPath)
                })
            # Start JCADMU Button
            $syncHash.StartJCADMUButton.Add_Click({
                    # Get the path of the exe then rerun
                    $exeFilePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
                    Start-Process -FilePath $exeFilePath
                    # Close the current window
                    $syncHash.CloseWindow = $true
                })

            $syncHash.ExitButton.Add_Click({
                    $syncHash.CloseWindow = $true
                })

            # Time to update the form
            $syncHash.Window.Add_SourceInitialized( {
                    $timer = new-object System.Windows.Threading.DispatcherTimer
                    $timer.Interval = [TimeSpan]"0:0:0.01"
                    $timer.Add_Tick( $updateForm )
                    $timer.Start()
                    if (!$timer.IsEnabled ) {
                        $clock.Close()
                        Write-Error "Timer didn't start"
                    }
                } )

            $syncHash.Window.Show() | Out-Null
            $appContext = [System.Windows.Forms.ApplicationContext]::new()
            [void][System.Windows.Forms.Application]::Run($appContext)
        })
    # Invoke PS Command
    $psCommand.Runspace = $newRunspace
    $data = $psCommand.BeginInvoke()

    Register-ObjectEvent -InputObject $SyncHash.Runspace -EventName 'AvailabilityChanged' -Action {
        if ($Sender.RunspaceAvailability -eq "Available") {
            $Sender.Closeasync()
            $Sender.Dispose()
        }
    } | Out-Null
    return $syncHash
}

# Function to update the progress bar
function Update-ProgressForm {
    param(
        [Parameter(Mandatory = $true)]
        $ProgressBar,
        [int]$PercentComplete,
        [string]$Status,
        [string]$logLevel,
        [string]$username,
        [string]$profileSize,
        [string]$localPath,
        [string]$newLocalUsername
    )

    if ($username -or $profileSize -or $localPath -or $newLocalUsername) {
        #Write-toLog -message "Migration details updated: Username: $username, ProfileSize: $profileSize, LocalPath: $localPath, NewLocalUsername: $newLocalUsername"
        $ProgressBar.UsernameInput = $username
        $ProgressBar.ProfileSizeInput = "$($profileSize)GB"
        $ProgressBar.LocalPathInput = $localPath
        $ProgressBar.NewLocalUsernameInput = $newLocalUsername
    }


    if ($logLevel -eq "Error") {
        $ProgressBar.PercentComplete = 100
        $ProgressBar.StatusInput = $Status
        $ProgressBar.logLevel = $logLevel
    } else {
        $ProgressBar.PercentComplete = $PercentComplete
        $ProgressBar.StatusInput = $Status

    }

}

function Update-LogTextBlock {
    param(
        [Parameter(Mandatory = $true)]
        $ProgressBar,
        [string]$LogText
    )
    # Update the progress bar and add XAML linebreaks
    $ProgressBar.LogText += $LogText
}
