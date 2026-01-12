---
external help file: JumpCloud.ADMU-help.xml
Module Name: JumpCloud.ADMU
online version: https://github.com/TheJumpCloud/jumpcloud-ADMU/wiki/Start-Reversion
schema: 2.0.0
---

# Start-Reversion

## SYNOPSIS
Reverts a user migration by restoring original registry files for a specified Windows SID.

## SYNTAX

```
Start-Reversion [-UserSID] <String> [[-TargetProfileImagePath] <String>] [-form <Boolean>] [-UserName <String>]
 [-ProfileSize <String>] [-LocalPath <String>] [-DryRun] [-Force] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This function reverts a user migration by:
1.
Looking up the account SID in the Windows registry ProfileList
2.
Identifying the .ADMU profile path
3.
Restoring original NTUSER.DAT and UsrClass.dat files from backups
4.
Preserving migrated files with _migrated suffix for rollback purposes

## EXAMPLES

### EXAMPLE 1
```
Start-Reversion -UserSID "S-1-5-21-123456789-1234567890-123456789-1001"
Reverts the migration for the specified user SID using the registry profile path.
```

### EXAMPLE 2
```
Start-Reversion -UserSID "S-1-5-21-123456789-1234567890-123456789-1001" -TargetProfileImagePath "C:\Users\john.doe"
Reverts the migration using a specific target profile path instead of the registry value.
```

### EXAMPLE 3
```
Start-Reversion -UserSID "S-1-5-21-123456789-1234567890-123456789-1001" -DryRun
Shows what would be reverted without making actual changes.
```

## PARAMETERS

### -UserSID
The Windows Security Identifier (SID) of the user account to revert.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TargetProfileImagePath
The actual profile path to revert.
If not specified, will use the path from the registry.
This path will be validated to ensure it exists and is associated with the UserSID.

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -form
{{ Fill form Description }}

```yaml
Type: System.Boolean
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserName
{{ Fill UserName Description }}

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProfileSize
{{ Fill ProfileSize Description }}

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LocalPath
{{ Fill LocalPath Description }}

```yaml
Type: System.String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DryRun
Shows what actions would be performed without actually executing them.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force
Bypasses confirmation prompts and forces the revert operation.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: System.Management.Automation.SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### [PSCustomObject] Returns revert operation results with success status and details.
## NOTES

## RELATED LINKS
