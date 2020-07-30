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
Start-Migration -JumpCloudUserName <String> -DomainUserName <String> -TempPassword <String>
 [-AcceptEULA <Boolean>] [-LeaveDomain <Boolean>] [-ForceReboot <Boolean>] [-AzureADProfile <Boolean>]
 [-Customxml <Boolean>] [-InstallJCAgent <Boolean>] [-JumpCloudConnectKey <String>] [<CommonParameters>]
```

### form
```
Start-Migration [-inputObject <Object>] [<CommonParameters>]
```

## DESCRIPTION
The Start-Migration function allows the starting of the JumpCloud Active Directory Migration Process. This utility can be used to convert domain bound user accounts into locally managed accounts ready to be taken over by JumpCloud. There are various options to run the utility depending on the administrators requirements.

## EXAMPLES

### Example 1
```powershell
PS C:\> Start-Migration -JumpCloudUserName 'john.smith' -DomainUserName 'jsmith' -TempPassword 'Temp123!' -AcceptEULA $true -LeaveDomain $true -ForceReboot $true -AZureADProfile $false -Customxml $false -InstallJCAgent $true -JumpCloudConnectKey 'CONNECTKEYHERE'

```

This example would run the `Start-Migration` function on a domain user `DOMAIN\jsmith` and create a new local user account `COMPUTERNAME\john.smith`. Using a temporary password `Temp123!`, accepting the EULA so no interactive prompts would display, the system would leave the bound domain and reboot, It is not converting a AzureAD profile or using a CustomXML for migration, It will also install the JumpCloud Agent and use the JumpCloud connect key provided.

### Example 2
```powershell
PS C:\> Start-Migration -JumpCloudUserName 'john.smith' -DomainUserName 'jsmith' -TempPassword 'Temp123!' -AcceptEULA $true -LeaveDomain $false -ForceReboot $false -InstallJCAgent $false

```

This example would run the `Start-Migration` function on a domain user `DOMAIN\jsmith` and create a new local user account `COMPUTERNAME\john.smith`. Using a temporary password `Temp123!`, accepting the EULA so no interactive prompts would display, the system would remain bound to the current domain, no reboot or JumpCloud Agent would be installed. This would allow the administrator to run the converted account in parallel for testing.

### Example 3
```powershell
PS C:\> Start-Migration -JumpCloudUserName 'john.smith' -DomainUserName 'jsmith' -TempPassword 'Temp123!' -AcceptEULA $true -LeaveDomain $false -ForceReboot $false -InstallJCAgent $false -Customxml $true

```

This example would run the `Start-Migration` function on a domain user `DOMAIN\jsmith` and create a new local user account `COMPUTERNAME\john.smith`. Using a temporary password `Temp123!`, accepting the EULA so no interactive prompts would display, the system would remain bound to the current domain, no reboot or JumpCloud Agent would be installed. This would allow the administrator to run the converted account in parallel for testing, A `Custom.XML` file would be used in the migration process from the location `C:\Windows\Temp\custom.xml` this could be edited from the default xml provided or the GUI utility could be used to edit.

`C:\Windows\Temp\custom.xml`

## PARAMETERS

### -AcceptEULA
A boolean $true/$false value for accepting Microsoft's Assessment and Deployment Kit (ADK) EULA. If $false the following log entry would be outputted.
LOG: 'Installing Windows ADK at C:\Program Files (x86)\Windows Kits\10\ please complete GUI prompts & accept EULA within 5mins or it will exit.'

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

### -AzureADProfile
A boolean $true/$false value to allow the conversion of AzureAD profile. This will set the domain account used in the migration to `AZUREAD\`.

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

### -Customxml
A boolean $true/$false value to allow the use of a custom.xml in the user state migration process. If $true USMT will look for `C:\Windows\Temp\Custom.xml` for additional migration steps.

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

### -DomainUserName
A string value for the DomainUserName that is used in the migration script. This value is verified to make sure the account exists on the system. If the Domain Account does not exist, the script will error and not continue.

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

### -ForceReboot
A boolean $true/$false value to force the system to reboot at the end of the migration process. A reboot is required when unbinding from a domain.

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
A boolean $true/$false value to install the JumpCloud agent on the system. If this value is $true you will be required to also pass a `JumpCloudConnectKey` value. If the system remains on the domain, the JumpCloud agent will be installed but not connected until it leaves the domain.

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
A string value that is required if `-InstallJCAgent` is $true. This connect key can be found in the JumpCloud console under add systems. It must be 24 chars and is different than an JumpCloud API key.

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
A string value that will be used for the new converted local account that can be bound to JumpCloud. This value must be unique on the system, if it is not unique an error will stop the migration. This value should match the JumpCloud Username value to allow takeover when a User is bound to a system within the JumpCloud console.

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
A boolean $true/$false value to force the system to leave currently bound domain, this is required for the JumpCloud Agent to operate. It can also be reversed by simply rejoining the system back to the domain. This will also work for AzureAD and will disconnect the AzureAD bind.

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
A string value that is used to set the new local accounts password. When duplicating the user account a password must be set when created and this value is passed. Once the system is online in JumpCloud the password will be overwritten and synced with JumpCloud if the user is taken over.

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
An PSObject can be passed to the function with the required values for the migration process. This is used when the GUI version of the tool is used and inputs to the XAML form are passed to this function.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### None
## OUTPUTS

### System.Object
## NOTES

## RELATED LINKS

[https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration](https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Migration)

