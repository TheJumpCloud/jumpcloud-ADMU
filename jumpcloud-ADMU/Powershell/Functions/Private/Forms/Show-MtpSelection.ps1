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