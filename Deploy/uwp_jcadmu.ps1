Add-Type -AssemblyName PresentationFramework
[xml]$xaml = @"
<Window
     xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
     xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
     Title="JumpCloud ADMU 1.5.0" Height="677.234" Width="1053.775" WindowStartupLocation="CenterScreen" ForceCursor="True" WindowState="Maximized" WindowStyle="None" Topmost="True"> 
    <Grid Name="Grid">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <Image Name="image" HorizontalAlignment="Left" Height="261" Margin="30,10,0,0" Grid.RowSpan="2" VerticalAlignment="Top" Width="515" Grid.Column="1" Source="https://www.fiber.net/wp-content/uploads/jumpcloud-logo-color.png"/>
        <Button Name="button" Content="Exit" Grid.Column="1" HorizontalAlignment="Left" Margin="185,355,0,0" Grid.Row="1" VerticalAlignment="Top"/>
        <Button Name="button1" Content="UWP Fix" Grid.Column="1" HorizontalAlignment="Left" Margin="750,365,0,0" Grid.Row="1" VerticalAlignment="Top"/>
    </Grid>
</Window>
"@
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$button = $window.FindName("button")
$button1 = $window.FindName("button1")

$button.Add_Click({
$window.close()
})

$button1.Add_Click({

$appxmanifest = ($HOME + '\AppData\Local\JumpCloudADMU\appx_manifest.csv')
$newList = Import-CSV $appxmanifest
foreach ($item in $newlist){
   Add-AppxPackage -DisableDevelopmentMode -Register "$($item.InstallLocation)\AppxManifest.xml"
}

})

$window.ShowDialog()