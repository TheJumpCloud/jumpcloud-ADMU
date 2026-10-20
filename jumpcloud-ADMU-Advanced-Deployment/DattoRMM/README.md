# Running ADMU from a Datto RMM component

`ADMU-Unified-Datto.ps1` is a Datto RMM component that runs the ADMU workflow on a device. It is an alternative to the JumpCloud command in `InvokeFromJCAgent`, for teams that already deploy with Datto RMM. It uses the same wave CSV and the same `gui_jcadmu.exe`.

It adds a diagnose step and a repair step for devices where an earlier run failed, and it runs ADMU from a scheduled task so the RMM job ending does not stop the migration.

## Modes

Set the `Mode` variable on the component.

| Mode | What it does |
| --- | --- |
| Diagnose | Default. Read-only. Classifies each user and prints the next step. |
| Remediate | Fixes what is safe to fix. See the state table. |
| Migrate | Runs Remediate, then migrates each ready user from the CSV. |

`DryRun` defaults to true. Set it to `false` to apply changes. In Diagnose mode nothing is changed either way.

## States

| State | Meaning | Action |
| --- | --- | --- |
| Ready | Domain profile intact. | Can be migrated. |
| StrayPreSwap | A failed run stopped before the profile swap and left an ADMU account and a `.000` profile. | Remediate removes the account and the profile after it checks that the domain profile is intact. |
| StrayNoProfile | An ADMU account with no profile. | Remediate removes the account. |
| MarkerStale | The domain hive still has `HKCU\Software\JCADMU` from a failed run. | Remediate backs up the hive and the key, then deletes the key. |
| NeedsPerms | Migration finished but the user lacks access to the profile root or Desktop. | Remediate repairs permissions. |
| Migrated | Finished, and access is fine. | None. |
| PostSwapDomainJoined | The profile swap happened and the device is still on the domain. | Manual. Use `Start-Reversion` if the user cannot sign in. |
| NameCollision | A local account with that name exists and ADMU did not create it. | Manual. |
| NoProfile | No domain profile for the user on this device. | None. |
| NeedsReview | A safety check failed. The detail names it. | Manual. |

Remediate and Migrate also unload `_admu` hives that an earlier run left loaded, and move leftover `NTUSER.DAT.BAK`, `UsrClass.dat.bak` and unused `.000` folders to `C:\ProgramData\ADMU-Unified`. Nothing is deleted. Backups of changed hives are in `C:\ProgramData\ADMU-Unified\hive-backups`, which only SYSTEM and Administrators can read.

## Datto variables

All are optional strings.

| Variable | Purpose |
| --- | --- |
| Mode | Diagnose, Remediate or Migrate. Default Diagnose. |
| DryRun | Default true. |
| TargetUsers | Comma-separated usernames, or ALL. Default ALL. |
| ForceLogoff | true logs users off before a permission repair. Default false. |
| RebootIfNeeded | true restarts in 5 minutes when a permission repair is blocked by a signed-in user, and registers a startup task to finish. Default false. |
| CsvName | The wave CSV attached to the component. Needed for Migrate. |
| JumpCloudAPIKey | Needed for Migrate. Leave blank to use system context binding. |
| JumpCloudOrgID | Needed with an MTP API key. |

Store `JumpCloudAPIKey` as a masked Datto variable. Rotate any key that was pasted into a chat or ticket.

## CSV

The headers are `SID`, `JumpCloudUserName`, `LocalComputerName` and `SerialNumber`. Rows are matched to the device by name and BIOS serial. System context binding also needs `JumpCloudUserID`. A CSV for `3_ADMU_Invoke.ps1` works as is.

## Behavior to know about

- Migrate refuses to start unless every CSV user for the device is Ready. Leaving the domain strands any domain profile that is not migrated, so it stops instead.
- Migrate logs off all sessions. Only the profiles being migrated must unload before ADMU starts. Other signed-in profiles are logged off and do not block the run.
- Migrate sets `LeaveDomain` and `RemoveMDM` only for the last user in the run, and restarts the device after 60 seconds by default. Change the settings block at the top of the script.
- The script downloads `gui_jcadmu.exe` from the latest GitHub release and checks the SHA256 digest when the release has one.
- The job file with the API key is written to `C:\ProgramData\ADMU-Unified`, restricted to SYSTEM and Administrators, and deleted when the run ends.
- Exit code 1 means at least one user is Failed or NeedsReview.

## Relation to the module

The `MarkerStale` step clears a leftover `JCADMU` key before ADMU runs. Newer ADMU module versions recognize a stale `PreviousSID` that equals the user's own SID and clear it themselves, and they restore the original hive files when a run fails before the swap. The script still helps with older versions and with leftover accounts and `.000` profiles.

## Example output

Names are placeholders.

```
[<time>] Start. Version=<version> Computer=<device> Mode=Diagnose DryRun=False Resume=False
[<time>] Domain joined: True. Domain or workgroup: <domain>
[<time>] Domain trust OK: True
[<time>] CSV <path>\<wave>.csv. Rows for this device: 1
[<time>] Summary

User   State        Plan    Result   Detail
----   -----        ----    ------   ------
<user> StrayPreSwap Cleanup ReadOnly Failed run stopped before the swap. Stray profile C:\Users\<user>.000. Domain profile C:\Users\<user>

[<time>] Start. Version=<version> Computer=<device> Mode=Remediate DryRun=False Resume=False
[<time>] Removing ADMU account <user> and profile C:\Users\<user>.000.
[<time>] <user>: cleanup done. State is now MarkerStale.
[<time>] <user>: Account removed. Domain profile intact.
[<time>] <user>: marker step done. State is now Ready.
[<time>] <user>: Removed the leftover JCADMU key. Backups: <hive-backups>\<user>-NTUSER-<ts>.DAT and <hive-backups>\<user>-JCADMU-<ts>.reg.
[<time>] <user>: Moved 10 leftover files to <hive-backups>\<user>-leftovers-<ts> and 0 unused folders to <quarantine>\<user>-<ts>.

User   State Plan    Result                       Detail
----   ----- ----    ------                       ------
<user> Ready Migrate Cleaned+MarkerCleared+Tidied Domain profile C:\Users\<user> intact. Ready to migrate.

[<time>] Start. Version=<version> Computer=<device> Mode=Migrate DryRun=False Resume=False
[<time>] Downloaded gui_jcadmu.exe v<release>.
[<time>] Started scheduled task ADMU-Unified-Migrate. It keeps running if this job ends.
[<time>] Migration task. Running: Migrating <user>
[<time>] Migration task. Succeeded: Migration finished. Restarting in 60 seconds.

User   State Plan    Result   Detail
----   ----- ----    ------   ------
<user> Ready Migrate Migrated Migration finished. Restarting in 60 seconds.
```

## Testing status

The Windows behavior was run on a small number of devices in one environment, with Diagnose, Remediate and Migrate each completing without manual steps. It has no Pester tests. Run it with `DryRun` true first.
