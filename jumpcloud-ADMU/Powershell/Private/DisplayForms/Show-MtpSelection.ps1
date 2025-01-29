function Show-MtpSelection {
    [CmdletBinding()]
    param (
        [Parameter()]
        [System.Object]
        $Orgs
    )

    begin {
        # define a class for Name/ ID pairs
        Class organization {
            [string]$Name
            [string]$ID

            organization([string]$Name, [string]$ID) {
                $this.Name = $Name
                $this.ID = $ID
            }
        }

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


        [xml]$XAML = @'
<Window
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="MTP Organization Selection"
        WindowStyle="SingleBorderWindow"
        ResizeMode="NoResize"
        Background="White"
        Height="180"
        Width="400">
    <Grid Margin="10,10,10,10">
        <Button x:Name="OKButton" Content="OK" HorizontalAlignment="Right" VerticalAlignment="Bottom" Width="60"/>
        <Button x:Name="CancelButton" Content="Cancel" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,0,70,0" Width="56"/>
        <ComboBox x:Name="ComboBoxOptions" HorizontalAlignment="Left" VerticalAlignment="Bottom" Width="120"/>
        <Label Content="Please Select A JumpCloud MTP:" HorizontalAlignment="Left" VerticalAlignment="Top"/>
        <Label x:Name="OrgName" Content="OrgName:" HorizontalAlignment="Left" Margin="0,26,0,0" VerticalAlignment="Top"/>

    </Grid>
</Window>

'@
    }
    process {

        # init list for building instances of the organization class
        $dataList = New-Object System.Collections.ArrayList
        # add each org item in the data list and cast those items as organization type items
        foreach ($org in $Orgs) {
            $dataList.Add(
                [organization]::new($org.DisplayName, $org._id)
            ) | Out-Null
        }
        # Read XAML
        $reader = (New-Object System.Xml.XmlNodeReader $xaml)
        Try {
            $Form = [Windows.Markup.XamlReader]::Load($reader)
        } Catch {
            Write-Error "Unable to load Windows.Markup.XamlReader. Some possible causes for this problem include: .NET Framework is missing PowerShell must be launched with PowerShell -sta, invalid XAML code was encountered.";
        }

        # Find and select items from the form
        $comboBox = $Form.FindName("ComboBoxOptions")
        $dynamicLabel = $Form.FindName("OrgName")
        $okButton = $Form.FindName("OKButton")
        $cancelButton = $Form.FindName("CancelButton")

        # Add keyValuePairs of data to the comboBox, necessary to display a name in the comboBox when receiving data from object
        foreach ($item in $dataList) {
            $keyValuePair = New-Object 'System.Collections.Generic.KeyValuePair[String, String]' ("$($item.ID)", "$($item.Name)")
            $comboBox.Items.Add($keyValuePair) | Out-Null
        }

        # Set the value of the comboBox items to the value of the keyValuePair items
        $comboBox.DisplayMemberPath = "Value"

        $combobox.Add_SelectionChanged({
                # update the orgName label when an item is selected from the comboBox
                $selectedItem = $comboBox.SelectedItem
                if ($selectedItem) {
                    $selectedId = $($SelectedItem.Key)
                    $selectedOrgName = $($SelectedItem.Value)
                    $dynamicLabel.Content = "OrgName: $selectedOrgName"
                }
            })

        # init variable for returning name and orgID
        $returnedOrg = [PSCustomObject]@{
            DisplayName = $null
            ID          = $null
        }

        $okButton.Add_Click({
                $selectedItem = $comboBox.SelectedItem
                if ($selectedItem) {
                    $returnedOrg.DisplayName = $($SelectedItem.Value)
                    $returnedOrg.ID = $($SelectedItem.Key)
                    $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                    $Form.Close()
                } else {
                    $dynamicLabel.Content = "OrgName: Please select an organization"
                }
            })
        $cancelButton.Add_Click({
                $Form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
                $Form.Close()

            })

        $result = $Form.ShowDialog()
    }
    end {

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $returnedOrg
        } else {
            return $null
        }
    }
}