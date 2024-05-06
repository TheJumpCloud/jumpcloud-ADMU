# Create a progres form runspace function
function New-ProgressForm{
    # Create a synchronized hashtable to store the form controls
    # Synchash the values
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName('presentationframework') | Out-Null
    $syncHash = [hashtable]::Synchronized(@{ })
    $newRunspace = [runspacefactory]::CreateRunspace()
    $syncHash.Runspace = $newRunspace
    $syncHash.PercentComplete = $PercentComplete
    $syncHash.StatusInput = ''
#     $synchash.xaml = @"
#     <Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
#         xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
#         Title="Migration Progress" Height="150" Width="300">
#         <Grid>
#             <ProgressBar Name="ProgressBar" Value="{Binding PercentComplete}" Height="20" VerticalAlignment="Top" Margin="10,10,10,0"/>

#             <TextBlock Name="PercentCompleteTextBlock" Visibility="Hidden" StackPanel.ZIndex = "99" Text="{Binding ElementName=ProgressBar, Path=Value, StringFormat={}{0:0}%}" HorizontalAlignment="Center" VerticalAlignment="Center" />
#              <TextBlock Name="Status" Text="" HorizontalAlignment="Left" />
#              <TextBlock Name="TimeRemaining" Text="" HorizontalAlignment="Left" />
#              <TextBlock Name="CurrentOperation" Text="" HorizontalAlignment="Left" />
#         </Grid>
#     </Window>
# "@

# $syncHash.XAML = @"
#       <Window
#           xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
#           xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
#           Name="Window" Title="Progress..." WindowStartupLocation = "CenterScreen"
#           Width = "560" SizeToContent = "Height" ShowInTaskbar = "True"
#           >
#           <StackPanel Margin="20">
#           <ProgressBar Name="ProgressBar" />
#              <TextBlock Name="PercentCompleteTextBlock" Visibility="Hidden" StackPanel.ZIndex = "99" Text="{Binding ElementName=ProgressBar, Path=Value, StringFormat={}{0:0}%}" HorizontalAlignment="Center" VerticalAlignment="Center" />
#              <TextBlock Name="Status" Text="" HorizontalAlignment="Left" />
#              <TextBlock Name="TimeRemaining" Text="" HorizontalAlignment="Left" />
#              <TextBlock Name="CurrentOperation" Text="" HorizontalAlignment="Left" />
#           </StackPanel>
#       </Window>
# "@
$syncHash.XAML = @"
        <Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="JumpCloud ADMU 2.7.0"
        WindowStyle="SingleBorderWindow"
        ResizeMode="NoResize"
        Background="White" ScrollViewer.VerticalScrollBarVisibility="Visible" ScrollViewer.HorizontalScrollBarVisibility="Visible" Width="540" Height="240">

        <Grid Margin="0,0,0,0">
        <Grid.RowDefinitions>
            <RowDefinition/>
        </Grid.RowDefinitions>

        <Image Name="JCLogoImg" HorizontalAlignment="Left" Height="33" VerticalAlignment="Top" Margin="9,0,0,0" Width="500"/>

        <TextBlock Name="Status" HorizontalAlignment="Center" Margin="0,129,0,0" TextWrapping="Wrap"  VerticalAlignment="Top" Width="212" Height="26"/>
        <ProgressBar Name="ProgressBar" HorizontalAlignment="Center" Height="44" Margin="0,68,0,0" VerticalAlignment="Top" Width="408"/>
        </Grid>
        </Window>
"@

    # Create a runspace to run the form in
    $newRunspace.ApartmentState = "STA"
    $newRunspace.ThreadOptions = "ReuseThread"
    $data = $newRunspace.Open() | Out-Null
    $newRunspace.SessionStateProxy.SetVariable("syncHash", $syncHash)

    # Create a powershell instance to run the form in
    # $ps = [powershell]::Create()
    # $ps.Runspace = $runspace

    # Add the form code to the powershell instance
    $psCommand = [PowerShell]::Create().AddScript({
        # Load an xaml form

        $syncHash.Window = [Windows.Markup.XamlReader]::parse( $SyncHash.XAML )
        ([xml]$SyncHash.XAML).SelectNodes("//*[@Name]") | % { $SyncHash."$($_.Name)" = $SyncHash.Window.FindName($_.Name) }
        # Get the progress bar and status textblock
        $updateBlock = {
            if ($SyncHash.ProgressBar.IsIndeterminate) {
                $SyncHash.PercentCompleteTextBlock.Visibility = [System.Windows.Visibility]::Hidden
            }
            else {
                $SyncHash.PercentCompleteTextBlock.Visibility = [System.Windows.Visibility]::Visible
            }


            if ($SyncHash.Closing -eq $True) {

                $SyncHash.NotifyIcon.Visible = $false
                $syncHash.Window.Close()
                [System.Windows.Forms.Application]::Exit()
                Break
            }


            $SyncHash.Window.Title = $SyncHash.Activity
            $SyncHash.ProgressBar.Value = $SyncHash.PercentComplete
            if ([string]::IsNullOrEmpty($SyncHash.PercentComplete) -ne $True -and $SyncHash.ProgressBar.IsIndeterminate -eq $True) {

                $SyncHash.ProgressBar.IsIndeterminate = $False

            }
            $SyncHash.Status.Text = $SyncHash.StatusInput
            if ($SyncHash.SecondsRemainingInput) {
                $TimeRemaining = [System.TimeSpan]::FromSeconds($SyncHash.SecondsRemainingInput)
                $SyncHash.TimeRemaining.Text = '{0:00}:{1:00}:{2:00}' -f $TimeRemaining.Hours, $TimeRemaining.Minutes, $TimeRemaining.Seconds
            }
            $SyncHash.CurrentOperation.Text = $SyncHash.CurrentOperationInput

            $SyncHash.NotifyIcon.text = "Activity: $($SyncHash.Activity)`nPercent Complete: $($SyncHash.PercentComplete)"

        }

        $syncHash.Window.Add_SourceInitialized( {
            ## Before the window's even displayed ...
            ## We'll create a timer
            $timer = new-object System.Windows.Threading.DispatcherTimer
            ## Which will fire 4 times every second
            $timer.Interval = [TimeSpan]"0:0:0.01"
            ## And will invoke the $updateBlock
            $timer.Add_Tick( $updateBlock )
            ## Now start the timer running
            $timer.Start()
            if ( $timer.IsEnabled ) {

            }
            else {
                $clock.Close()
                Write-Error "Timer didn't start"
            }
        } )

        $Synchash.window.Add_Closing( {

            if ($SyncHash.Closing -eq $True) {

            }
            else {

                $SyncHash.Window.Hide()
                $SyncHash.NotifyIcon.BalloonTipTitle = "Your script is still running..."
                $SyncHash.NotifyIcon.BalloonTipText = "Double click to open the progress bar again."
                $SyncHash.NotifyIcon.ShowBalloonTip(100)
                $_.Cancel = $true

            }

        })

        $syncHash.Window.Show() | Out-Null
          $appContext = [System.Windows.Forms.ApplicationContext]::new()
          [void][System.Windows.Forms.Application]::Run($appContext)
          $syncHash.Error = $Error


    })

    $psCommand.Runspace = $newRunspace
    $data = $psCommand.BeginInvoke()


    Register-ObjectEvent -InputObject $SyncHash.Runspace `
        -EventName 'AvailabilityChanged' `
        -Action {

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
        [string]$Status
    )

    # Update the progress bar
    $ProgressBar.PercentComplete = $PercentComplete
    $ProgressBar.StatusInput = $Status

}