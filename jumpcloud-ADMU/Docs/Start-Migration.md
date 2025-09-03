---
external help file: JumpCloud.ADMU-help.xml
Module Name: JumpCloud.ADMU
online version: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration
schema: 2.0.0
---

# Start-Migration

## SYNOPSIS

Starts the JumpCloud Active Directory Migration process.

## SYNTAX

### cmd
```
Start-Migration -JumpCloudUserName <String> -SelectedUserName <String> -TempPassword <String>
 [-LeaveDomain <Boolean>] [-ForceReboot <Boolean>] [-UpdateHomePath <Boolean>] [-InstallJCAgent <Boolean>]
 [-AutoBindJCUser <Boolean>] [-BindAsAdmin <Boolean>] [-SetDefaultWindowsUser <Boolean>]
 [-AdminDebug <Boolean>] [-JumpCloudConnectKey <String>] [-JumpCloudAPIKey <String>] [-JumpCloudOrgID <String>]
 [-ValidateUserShellFolder <Boolean>] [<CommonParameters>]
```

### form
```
Start-Migration [-inputObject <Object>] [<CommonParameters>]
```

## DESCRIPTION

The Start-Migration function allows the starting of the JumpCloud Active Directory Migration Process.
This utility can be used to convert domain bound user accounts into locally managed accounts ready to be taken over by JumpCloud.
There are various options to run the utility depending on the administrators requirements.

## EXAMPLES

### Example 1

```
PS C:\> Start-Migration -SelectedUserName 'DOMAIN\bobfay' -JumpCloudUserName 'bob.fay' -TempPassword 'Temp123!Temp123!' -LeaveDomain $true -ForceReboot $true -InstallJCAgent $true -JumpCloudConnectKey 'ConnectKEY' -AutobindJCUser $true -JumpCloudAPIKey 'APIKEY'
```

This example would run the \`Start-Migration\` function on a domain user \`DOMAIN\bobfay\` and create a new local user account \`COMPUTERNAME\bob.fay\`.
Using a temporary password \`Temp123!Temp123!\`.
The JumpCloud Agent would be installed.
After migration the JumpCloud user \`bob.fay\` would be bound to the system.
Finally, the system would leave the bound domain and reboot.

### Example 2

```
PS C:\> Start-Migration -SelectedUserName 'DOMAIN\bobfay' -JumpCloudUserName 'bob.fay' -TempPassword 'Temp123!Temp123!' $false -ForceReboot $false -InstallJCAgent $false
```

This example would run the \`Start-Migration\` function on a domain user \`DOMAIN\jsmith\` and create a new local user account \`COMPUTERNAME\john.smith\`.
Using a temporary password \`Temp123!Temp123!\`, the system would remain bound to the current domain and not reboot.
The JumpCloud Agent would not be installed.
This would allow the administrator to run the converted account in parallel for testing.

## PARAMETERS

### -ForceReboot

A boolean $true/$false value to force the system to reboot at the end of the migration process.
A reboot is required when unbinding from a domain.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InstallJCAgent

A boolean $true/$false value to install the JumpCloud agent on the system.
If this value is $true you will be required to also pass a \`JumpCloudConnectKey\` value.
If the system remains on the domain, the JumpCloud agent will be installed but not connected until it leaves the domain.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -JumpCloudConnectKey

A string value that is required if \`-InstallJCAgent\` is $true.
This connect key can be found in the JumpCloud console under add systems.
It must be 24 chars and is different than an JumpCloud API key.

```yaml
Type: System.String
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -JumpCloudUserName

A string value that will be used for the new converted local account that can be bound to JumpCloud.
This value must be unique on the system, if it is not unique an error will stop the migration.
This value should match the JumpCloud Username value to allow takeover when a User is bound to a system within the JumpCloud console.

```yaml
Type: System.String
Parameter Sets: cmd
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LeaveDomain

A boolean $true/$false value to force the system to leave currently bound domain, this is required for the JumpCloud Agent to operate.
It can also be reversed by simply rejoining the system back to the domain.
This will also work for AzureAD and will disconnect the AzureAD bind.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TempPassword

A string value that is used to set the new local accounts password.
When duplicating the user account a password must be set when created and this value is passed.
Once the system is online in JumpCloud the password will be overwritten and synced with JumpCloud if the user is taken over.

```yaml
Type: System.String
Parameter Sets: cmd
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -inputObject

An PSObject can be passed to the function with the required values for the migration process.
This is used when the GUI version of the tool is used and inputs to the XAML form are passed to this function.

```yaml
Type: System.Object
Parameter Sets: form
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SelectedUserName

A string value for the DomainUserName that is used in the migration script.
This value is verified to make sure the account exists on the system.
If the Domain Account does not exist, the script will error and not continue.
Either pass a username using the "Domain\username" syntax or a domain user SID.

```yaml
Type: System.String
Parameter Sets: cmd
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UpdateHomePath

If set to $true, the ADMU will attempt to rename the selected username's homepath to the jumpcloud username.
Note, this could break any applications that rely on a hard coded homepath.
By default this is not set and will not rename the homepath.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -JumpCloudAPIKey

The Read/Write API key of a JumpCloud Administrator.
This parameter is required if the AutoBind JC User parameter is specified.

```yaml
Type: System.String
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -JumpCloudOrgID

The ID of the JumpCloud Organization you wish to connect to.
This field is only required if an MTP Api Key is used in the JumpCloudApiKey Parameter

```yaml
Type: System.String
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -BindAsAdmin

Option to bind user as sudo administrator or not.
This parameter is not required and will default to $false (User will not be bound as admin).
Set to $true if you'd like to bind the JumpCloudUserName as administrator during migration.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SetDefaultWindowsUser

Option to set the windows default login user to the migrated user post-migration.
This parameter is not required and will default to $true (the next login window user will be the migrated user).
Set to $false if you'd like to disable this functionality during migration.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdminDebug

Option to display detailed messages during migration.
This parameter is optional, but if set to $true, the CLI will show verbose output during the migration process

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ValidateUserShellFolder

Option to bypass User Shell Folder validation.
When set to \`$false\`, the migration will not verify whether folders (Desktop, Downloads, Documents, Videos, Pictures, Music, Favorites) are redirected to another location, such as a network shared folder (e.g., \`\192.168.50.78\SharedFolder\USERNAME\Desktop\`).
Use this parameter with caution.
After migration, the user may encounter a shared folder error and will need to provide account credentials to restore their shared folders

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AutoBindJCUser

This parameter will bind the username specified in the \`JumpCloudUserName\` field to the current system after Migration.

```yaml
Type: System.Boolean
Parameter Sets: cmd
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS

[https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration)

