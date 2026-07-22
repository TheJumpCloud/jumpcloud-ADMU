# Code Review Agent Instructions — jumpcloud-ADMU

> **Purpose**: Instructions for an AI code review agent to review pull requests in this repository as a Principal-level engineer with deep knowledge of JumpCloud’s Active Directory Migration Utility (ADMU).
>
> **Generated**: 2026-07-22 — derived from **232** merged PRs (**896** line review comments, **~589** human; **239** substantive review bodies; **28** issue comments; **0** API failures), plus Cursor Bugbot / Copilot / CodeRabbit titles, CODEOWNERS, CI, and codebase analysis.
>
> **Sample caveat**: Absolute PR count is below the usual 300–500 playbook target, but human line-comment volume is strong. Nearly all historical human signal is on PowerShell / Deploy / Advanced-Deployment; the native .NET rewrite under `src/` is newer — weight recurring PowerShell themes highest, and ground native checks in the current stack + design docs rather than inventing process from other JumpCloud repos.

---

## 1. Agent Behavior & Review Protocol

### Review Focus Priority (highest → lowest)

1. **Logic Errors** — terminating vs non-breaking failures, phase ordering (e.g. leave-domain before bind), unreachable/`break` after `throw`, wrong SID/`.bak` registry lifecycle, GUI/CLI parameter mismatch
2. **Security** — API keys / connect keys / temp passwords in code, tests, or logs; DPAPI job secrets; privilege (admin/SYSTEM); MDM removal protecting JumpCloud enrollments; EXE download validation where product expects it
3. **Reliability** — hive load/unload/rename, NTFS ACL traversal (throw vs continue, reparse points), Windows service install/self-uninstall, progress heartbeats on long steps, handle dispose / readonly registry opens
4. **Windows AD migration domain** — AD/Entra → local profile conversion, reversion, AutoBind / System Context bind, leave-domain + LogonUI, UWP/Appx helper, scheduled-task / login-block restore
5. **Tests & maintainability** — Pester acceptance for new PowerShell functions; xUnit for native Shared changes; ModuleChangelog delta-only; Deploy EXE template param sync

### Rules

| Rule | Detail |
|------|--------|
| **Scope** | Only comment on lines that are part of the diff. Never comment on unchanged code. |
| **No filler** | No "looks good", no summary preamble. If the PR is clean, return `[]`. |
| **Compilable suggestions** | Every `suggestion` must be a drop-in replacement (or clear multi-line PowerShell/C# patch). |
| **One comment per issue** | Do not duplicate findings for the same root cause. |
| **Be specific** | Reference exact function/type/parameter names. |
| **Respect existing rules** | Apply `.cursor/rules/**` and any `BUGBOT.md` reminders if present. Repo rules win on conflict. |
| **Avoid bot duplicates** | Skip issues already raised by Bugbot, Cursor, Copilot, CodeRabbit, or humans on the same root cause. |

### Structured Output Format

```json
[
  {
    "file_path": "jumpcloud-ADMU/Powershell/Public/Start-Migration.ps1",
    "line_number": 120,
    "severity": "CRITICAL | WARNING | NITPICK",
    "category": "SECURITY | PERFORMANCE | LOGIC | CONCURRENCY | MAINTAINABILITY | CONFIGURATION | TESTING | CROSS_PLATFORM",
    "comment": "Concise explanation of the problem and its impact.",
    "suggestion": "# compilable replacement code"
  }
]
```

### Review modes

| Mode | When | Output |
|------|------|--------|
| **GitHub PR review** | User provides a PR number | Findings JSON, then **post** line comments |
| **Local / advisory** | Branch/working-tree diff, no PR | Findings JSON in chat only — **do not** post |

### Posting Comments (GitHub PR mode only)

In **local / advisory** mode, skip this entire subsection.

| Property | Value |
|----------|-------|
| **Owner** | `TheJumpCloud` |
| **Repository** | `jumpcloud-ADMU` |
| **Default reviewers** | `@TheJumpCloud/customer-tools` (CODEOWNERS) |

#### Comment Template

```
**{SEVERITY} — {CATEGORY}**: {comment}

**Suggestion**:
```powershell
{suggestion code}
```

_Comment created by JC-ReviewAgent_
```

Use a `csharp` fence when suggesting C# changes. If findings are `[]`, post nothing.

### Multi-Model Review Protocol

| Pass | Model | Strengths |
|------|-------|-----------|
| **Pass 1** | `Grok 4.5` | Deep / long-running review — migration semantics, hive/ACL safety, privilege |
| **Pass 2** | `Composer 2.5` | Fast second pass for GUI/CLI parity, Pester/xUnit gaps, changelog/template nits |

First-party pool (same as Auto). For API-pool higher effort: **Claude Opus 4.8** then **Gemini 3.1 Pro**. Select models explicitly — do not leave both passes on Auto.

1. Pass 1 runs the full review.
2. Pass 2 gets Pass 1 findings as context and must find **new** issues only.
3. **GitHub PR mode only:** Pass 1 posts findings; Pass 2 posts only net-new findings.
4. **Local / advisory mode:** both passes return findings in chat only — **never** post to GitHub. This overrides any other “post findings” language.
5. Select the two models **explicitly** — do not leave both passes on Auto.

### Re-reviews (GitHub PR mode only)

1. Focus on latest changes.
2. Verify prior `JC-ReviewAgent` threads; resolve or reactivate with `Re-activated —`.
3. Do not duplicate other reviewers.
4. Summarize resolved vs open vs new.

---

## 2. Repository Overview

### What This Repo Is

**jumpcloud-ADMU** — JumpCloud Active Directory Migration Utility. It converts **Active Directory** or **Entra ID / Azure AD**–joined Windows user profiles to **local accounts** so the JumpCloud agent can manage them. Product surfaces include the classic PowerShell module + PS2EXE `gui_jcadmu.exe` / `uwp_jcadmu.exe`, remote Invoke scripts under Advanced-Deployment, and a native .NET 8 bootstrapper + ephemeral Windows service + WPF GUI under `src/`.

### Architecture

```
Admin (GUI / CLI / JumpCloud Command)
        |
        +-- Classic: gui_jcadmu.exe (PS2EXE) --> Start-Migration / Start-Reversion
        |         +-- Private helpers (registry, ACL, API, forms, UWP download)
        |         +-- uwp_jcadmu.exe (first-login Appx restore)
        |
        +-- Native: JumpCloud.ADMU.Gui.exe
                  --> elevates JumpCloud.ADMU.Bootstrapper.exe
                  --> installs JumpCloud.ADMU.Worker.exe service (LocalSystem)
                  --> job under %ProgramData%\JumpCloud\ADMU\jobs\{jobId}\
                  --> DPAPI secrets.dpapi + status.json + jcAdmu.log compat log
                  --> Bootstrapper --cleanup uninstalls service
```

Key runtime concepts:

- **Destructive migration pipeline** — backup hives, create local user/profile, ACL + registry copy, ProfileList reassignment, optional leave-domain / MDM remove / AutoBind / System Context bind / reboot.
- **Failure semantics matter** — some steps must fail hard (data prep / no users for Invoke); others must warn-and-continue (e.g. UWP download historically non-breaking).
- **Dual stack during cutover** — PowerShell remains the historical shipping path; native rewrite targets parity (see `docs/design/native-rewrite.md`).
- **Customer-facing logs** — prefer a single `jcAdmu.log` stream for supportability.

### Major Packages / Areas

| Area | Paths | Role |
|------|-------|------|
| Public migration API (PS) | `jumpcloud-ADMU/Powershell/Public/Start-Migration.ps1`, `Start-Reversion.ps1` | Main migrate/revert entrypoints |
| Private helpers (PS) | `jumpcloud-ADMU/Powershell/Private/**` | Registry, permissions, API, forms, MDM, Appx, SystemContext |
| GUI (classic) | `Private/DisplayForms/**`, legacy `Form.ps1` / `ProgressForm.ps1` | WinForms-style selection + progress |
| Deploy / EXE | `Deploy/**`, especially `Functions/New-ADMUTemplate.ps1`, `uwp_jcadmu.ps1`, `Build*.ps1` | PS2EXE build, template params, UWP helper |
| Remote Invoke | `jumpcloud-ADMU-Advanced-Deployment/InvokeFromJCAgent/**` | Agent-driven bulk migrate (`3_ADMU_Invoke.ps1`, DeviceInit) |
| Changelog / module | `ModuleChangelog.md`, `jumpcloud-ADMU/JumpCloud.ADMU.psd1` | Release notes + module manifest |
| Native shared | `src/JumpCloud.ADMU.Shared/**` | Pipeline, Windows services, JC API, validation, DPAPI, job IO |
| Native bootstrapper | `src/JumpCloud.ADMU.Bootstrapper/**` | CLI, service install/cleanup, job launch |
| Native worker | `src/JumpCloud.ADMU.Worker/**` | Ephemeral Windows service running migration |
| Native GUI | `src/JumpCloud.ADMU.Gui/**` | WPF UI elevating bootstrapper |
| Native tests | `src/JumpCloud.ADMU.Shared.Tests/**` | xUnit |
| Design | `docs/design/native-rewrite.md` | Native architecture & phase coverage |
| CI | `.github/workflows/admu-ci.yml`, `admu-release.yml` | Module CI (ADMU + version labels) |

### Tech Stack (inventory)

| Layer | Choices | Locations |
|-------|---------|-----------|
| Classic language | **PowerShell** module | `jumpcloud-ADMU/Powershell/**` |
| Native language | **C# / .NET 8** (`net8.0-windows`), Nullable enabled | `src/**/*.csproj` |
| Native UI | **WPF** | `JumpCloud.ADMU.Gui` |
| Native host | **Generic Host** + Windows Service | `JumpCloud.ADMU.Worker` |
| Native CLI | **System.CommandLine** | Bootstrapper |
| Windows APIs | DirectoryServices, Management/WMI, ACL, DPAPI, ServiceController | Shared `Windows/`, `Security/`, packages |
| Classic tests | **Pester** (+ PSScriptAnalyzer in CI) | `Powershell/Tests/**` |
| Native tests | **xUnit** + coverlet | `JumpCloud.ADMU.Shared.Tests` |
| Packaging | PS2EXE / Deploy scripts; `dotnet publish` win-x64 self-contained | `Deploy/`, `src/README.md` |
| CI | GitHub Actions on **Windows-2022** (module); release workflow | `.github/workflows/` |
| Platform | **Windows only** (AD/Entra migration) | entire product |

---

## 3. Security-Critical Review Areas

### 3.1 Secrets & credentials

- JumpCloud **API keys**, **connect keys**, and **temp passwords** must not appear in committed tests, sample scripts, DeviceInit helpers, or logs.
- Prefer env/secure input patterns already used by the team; flag hardcoded keys and “paste API key here” leftovers.
- Native jobs store secrets via **DPAPI LocalMachine** (`SecretProtector` → `secrets.dpapi`) — flag plaintext secret writes beside that path.

### 3.2 Privilege & SYSTEM

- Migration often runs elevated or as **LocalSystem** (native Worker). Flag accidental privilege drops, UAC manifest regressions, and cleanup that leaves the service installed.
- Deferred NTFS permission tasks and login-block policies are machine-wide — backup/restore correctness is a security/availability issue.

### 3.3 MDM / domain leave

- MDM removal must **preserve JumpCloud enrollments** (bot + human theme: protection removed / orphan GUID handling).
- Leave-domain + bind ordering: AutoBind / SystemContext paths historically require leave-domain; GUI must not let admins deselect forced options.

### 3.4 Download / EXE trust

- Remote Invoke SHA validation and local EXE supply are product-sensitive; do not casually remove validation without matching intentional product decisions, and do not make historically non-breaking UWP download failures terminating without explicit product buy-in.

---

## 4. Code Quality Standards

There is no committed `.cursor/rules` set yet. Standards below come from human review nits + toolchain.

### Dependencies / DI

- Native: prefer constructor injection and interfaces for pipeline/services; validate required dependencies in constructors.
- **Do not** recommend method-level null guards for always-required deps after construction.
- PowerShell: keep Private helpers testable (separate functions that Pester can mock — e.g. do not inline `Invoke-NativeTreeAcl` solely for neatness if tests depend on the seam).

### Logging / errors

- Prefer **one customer log**: `jcAdmu.log` / `Write-ToLog` / native `CompatibilityLog` — avoid new ad-hoc log files that fragment support bundles.
- Actionable `Write-Error` / throw messages for hive permission failures (admin rights, processes locking NTUser.dat/UsrClass.dat).
- Distinguish **terminating** vs **non-breaking** failures; do not escalate optional steps to hard throws without product rationale.
- Avoid `exit` inside functions that should `throw` so EXE/host error handling can run; conversely, Invoke data-prep may intentionally `exit 1`.

### Concurrency / long-running work

- Long NTFS permission passes need progress/heartbeat so GUI/CLI/device description does not look hung.
- Be cautious starting permission work as a separate process unless heartbeat/timing requires it — discuss trade-offs.
- GUI must not freeze (TEMP user / greyed controls) when migration cannot proceed; surface errors instead of dead UI.

### PowerShell structure

- New Private functions → matching Acceptance tests under the mirrored Tests path; use Deploy test scaffolding / `build.ps1` conventions.
- Prefer `begin`/`process`/`end` and consistent return definitions on auth helpers so callers can reason about outputs.
- Avoid unnecessary `break` after `throw`.
- Prefer readonly registry opens when not writing; dispose/close handles.

---

## 5. Architecture & Design Patterns

- **Phase pipeline** — native `RealMigrationPipeline` / `MigrationPhases`; PowerShell `Start-Migration` orchestrates the same conceptual phases. Keep ordering intentional (e.g. leave domain before bind).
- **Job artifacts (native)** — `%ProgramData%\JumpCloud\ADMU\jobs\{jobId}\` with `status.json` + DPAPI secrets; bootstrapper owns service lifecycle.
- **Parity during cutover** — changes to classic behavior should consider native Shared services (`RegistryHiveService`, `NtfsPermissionService`, `MdmRemovalService`, etc.) and vice versa when touching migration semantics.
- **EXE parameter surface** — Public/CLI params must stay in sync with `Deploy/Functions/New-ADMUTemplate.ps1` or the PS2EXE binary will not expose them.
- **GUI mirrors CLI invariants** — forced parameters (AutoBind ⇒ leave domain) should be checked **and** disabled in the form.
- **Advanced-Deployment** scripts are customer-facing remote automation; treat exit codes and device-description CSV/JSON parsing as production contracts.

---

## 6. Testing Requirements

### PowerShell (Pester)

- New Private/Public functions should ship with Acceptance tests (human theme: “when we create new functions, we also create tests”).
- Place tests in the directory that mirrors Private/Public layout; do not leave Authentication tests under JumpCloudApi, etc.
- Prefer mocks for network/API; **do not** embed real API keys or durable temp passwords in tests.
- Update `invokeMigration.Tests.ps1` / character-limit checks when Invoke scripts grow.
- Manual GUI scenarios may live under `Tests/manualTests/*.feature` — still validate Migrate button enablement vs validation errors.

### Native (xUnit)

- Risky Shared changes (hive files, SID resolve, validators, job store, NTFS, pipeline stubs) should extend `JumpCloud.ADMU.Shared.Tests`.
- Prefer `--validateOnly` / `--stubPipeline` / `--spike` for non-destructive verification guidance in PR test plans — do not require reviewers to run real domain migrations in CI comments.

### General

- If behavior order matters (leave-domain then bind), prefer assertions on sequence (`Assert-MockCalled` order) when practical — noted as a gap in human reviews.

---

## 7. Package & Dependency Management

- Native NuGet refs live in `*.csproj` (e.g. DirectoryServices, ProtectedData, Hosting.WindowsServices, System.CommandLine) — justify new packages; keep `net8.0-windows`.
- PowerShell module version + `ModuleChangelog.md` must move together on release PRs.
- Do not UTF-16-encode manifests in ways that break git diff/`grep` without cause (historical Build-Module lesson).
- Dual-publish native artifacts: wipe output dir before `dotnet publish` to avoid SxS mix (see `src/README.md`).

---

## 8. PR Hygiene & Process

- Default branch: **`master`**.
- PR template: Jira link, problem statement, tricky bits, test plan, screenshots.
- CODEOWNERS: `@TheJumpCloud/customer-tools`.
- Module CI requires **`ADMU`** label plus exactly one of `major` / `minor` / `patch` / `manual`.
- CI currently pins **Windows-2022** for module builds — do not casually flip runner images without the documented dependency rationale.
- `ModuleChangelog.md`: add the release delta only; do not rewrite the entire file in a feature PR.
- Prefer screenshots for GUI changes (team review culture).

---

## 9. Technology Inventory & Best-Practice Checks

### 9.0 Quick checklist

- [ ] Terminating vs non-breaking failure semantics match existing migration behavior
- [ ] No API keys / connect keys / temp passwords in code, tests, or logs
- [ ] Registry hive / `.bak` SID lifecycle cannot destroy the updated profile association
- [ ] NTFS/ACL traversal: warn-and-continue where throws would abort mid-tree; reparse skips logged
- [ ] MDM removal still protects JumpCloud enrollments
- [ ] GUI forced options are checked **and** greyed when CLI would force them
- [ ] New PowerShell functions have Pester tests; native Shared risks have xUnit coverage
- [ ] New EXE/CLI params updated in `New-ADMUTemplate.ps1` when classic EXE surface changes
- [ ] Customer logs stay on the single `jcAdmu.log` / CompatibilityLog path
- [ ] Login-block / scheduled-task / credential-provider backups restore on failure paths
- [ ] Required deps enforced in constructors (native); no ritual null checks for required services

### 9.1 PowerShell module & Start-Migration

| Check | Flag if |
|-------|---------|
| Failure escalation | Optional step (e.g. UWP download) newly `throw`s / terminates migration without product rationale |
| Dead control flow | `break` after `throw`, or unreachable branches |
| Param gating | Username/API checks run when AutoBind/APIKey not in play |
| Log fragmentation | New log file path instead of `Write-ToLog` / `jcAdmu.log` |
| Error quality | Generic failures without hive permission / process-lock guidance where siblings are specific |
| Script scope | `$script:` debug/log flags initialized after consumers read them |

### 9.2 Registry hives & ProfileList

| Check | Flag if |
|-------|---------|
| `.bak` lifecycle | Deletes/renames `.bak` ProfileList keys regardless of update success |
| SID suffix | Feeds `S-1-5-…\.bak` into `SecurityIdentifier` without stripping |
| Load/unload | Missing permission / process checks around NTUser.dat / UsrClass.dat |
| Domain leave identity | Translates names that fail after leave-domain instead of using SIDs |
| Readonly | Opens writable registry keys when only reading |

### 9.3 NTFS ACL / permissions

| Check | Flag if |
|-------|---------|
| Traversal abort | Throw on a single item stops entire permission walk |
| Reparse points | Symlink/reparse skip leaves required permissions unset with no log |
| Rights check | Allow-only checks miss FullControl |
| Deferred fallback | Immediate ACL failure with no scheduled-task / first-login fallback when product expects one |
| Heartbeat | Long permission step with no progress/device-description heartbeat |
| Path spaces | Broken quoting for profile paths containing spaces |

### 9.4 GUI / progress / EXE template

| Check | Flag if |
|-------|---------|
| Forced options | AutoBind path leaves LeaveDomain unchecked or still user-toggleable |
| Button enablement | Migrate enabled while validation errors remain |
| Progress init | Progress bar/XAML used before initialization |
| TEMP / loaded user | UI freezes greyed with no actionable error |
| Template sync | New public param not added to `Deploy/Functions/New-ADMUTemplate.ps1` |
| ExecutionPolicy | Script changes machine ExecutionPolicy unnecessarily |

### 9.5 JumpCloud API / System Context / regions

| Check | Flag if |
|-------|---------|
| Region URLs | Wrong host regex / trailing slash / orgID empty edge cases for EU/IN/etc. |
| SystemContext | Leave-domain / bind ordering wrong for `systemContextBinding` |
| Silent swallow | Connectivity errors swallowed; placeholder API keys set env unnecessarily |
| Body typing | `ContainsKey` on non-hashtable response bodies |

### 9.6 MDM / domain leave / login policy

| Check | Flag if |
|-------|---------|
| JC enrollment | Removal path can delete JumpCloud MDM enrollment |
| Partial disable | Login block / credential provider disable without restore on failure |
| Computer-wide backup | Per-user backup for machine-wide credential provider settings |
| WMI→CIM | Mock/tests not updated with provider change |

### 9.7 UWP / Appx / downloads

| Check | Flag if |
|-------|---------|
| Non-breaking download | UWP helper download failure becomes terminating |
| Null Appx | Starts import job when Appx list null/missing |
| SHA / local EXE | Validation removed or local-EXE supply broken for Invoke rate-limit scenarios |
| Retry params | Declared retry delay ignored |

### 9.8 Advanced-Deployment / Invoke

| Check | Flag if |
|-------|---------|
| Exit codes | “No users to migrate” / data-prep errors no longer fail Invoke (`exit 1`) when expected |
| Device description | JSON/object descriptions break CSV round-trip parsers |
| Secrets | API keys embedded in DeviceInit scripts |
| Filter scale | Missing org-scale filters that prior reviews required |

### 9.9 Native .NET (`src/`)

| Check | Flag if |
|-------|---------|
| Service lifecycle | Worker install without reliable `--cleanup` / self-uninstall |
| Secrets | Job secrets written plaintext instead of DPAPI LocalMachine |
| Pipeline parity | Phase skipped/reordered vs `docs/design/native-rewrite.md` / PowerShell Start-Migration without note |
| Progress | Native path ignores progress heartbeat while classic emits one |
| Validation | `--validateOnly` / runtime validators bypassed on destructive paths |
| Publish hygiene | Partial publish mixing outputs (SxS) instructions ignored in scripts |
| Nullable | New null-forgiving spam hiding real optional secret/path bugs |

### 9.10 Testing (Pester + xUnit)

| Check | Flag if |
|-------|---------|
| Missing Pester | New PS function without Acceptance test |
| Wrong test folder | Test not mirrored under matching Private/Public area |
| Secrets in tests | API keys / real passwords committed |
| Mock drift | Production switched WMI/CIM/API shape but mocks/asserts not updated |
| Native coverage | Hive/SID/validator/pipeline changes with no xUnit updates |

### 9.11 CI / release / changelog

| Check | Flag if |
|-------|---------|
| Changelog rewrite | Entire `ModuleChangelog.md` reformatted instead of delta |
| Label contract | CI label assumptions broken (`ADMU` + single version label) |
| Runner flip | `windows-latest` change without dependency rationale |
| Version skew | GUI/module/version strings diverge intentionally undocumented |

### 9.12 Cross-platform note

| Check | Flag if |
|-------|---------|
| Non-Windows abstractions | Heavy cross-platform layering in this Windows-only product without need |
| CROSS_PLATFORM category | Use sparingly — prefer SECURITY/LOGIC/CONFIGURATION for Windows migration issues |

---

## 10. Common Review Anti-Patterns

Derived from human reviewers and bots across **232** merged PRs (**~589** human line comments).

| Anti-Pattern | How to Spot It | What to Say |
|---|---|---|
| **Terminating optional failure** | `throw`/`exit` on UWP download or similar historically non-breaking step | "Keep this non-terminating; log and continue so migration still completes when the helper can run later." |
| **ACL traversal abort** | Throw inside recursive permission walk | "Warn and continue; a single item failure must not stop permission traversal." |
| **`.bak` registry destruction** | Delete/rename ProfileList `.bak` without success checks | "Only remove/rename `.bak` after the updated profile association is confirmed." |
| **SID `.bak` suffix** | Passes `*.bak` SID string into `SecurityIdentifier` | "Strip the `.bak` suffix before constructing the SID." |
| **Login block not restored** | Early throw after disabling credential providers / deny-logon | "Restore login policy in `finally`/error paths so a failed migration cannot leave interactive logon blocked." |
| **MDM removes JumpCloud** | Enrollment filter dropped | "Preserve JumpCloud MDM enrollments; only remove non-JC providers." |
| **GUI/CLI invariant drift** | CLI forces LeaveDomain on AutoBind but GUI still allows uncheck | "Check and disable LeaveDomain when AutoBind/SystemContext requires it." |
| **Progress before init** | Progress bar/heartbeat used before form/status init | "Initialize progress UI before updates; native paths should keep heartbeats too." |
| **Secret in repo** | API key/password in tests or DeviceInit scripts | "Remove the secret; load from secure input/env like our other helpers." |
| **Changelog file rewrite** | Mass rewrite of `ModuleChangelog.md` | "Revert unrelated changelog churn; add only this release’s delta." |
| **EXE template skew** | New Start-Migration param not in `New-ADMUTemplate.ps1` | "Add the parameter to the EXE template or the PS2EXE build will not expose it." |
| **Missing Pester for new function** | New Private function, no Acceptance test | "Add a mirrored Acceptance test; we require tests when we add functions." |
| **Log file splintering** | New dedicated log path for one subsystem | "Write to jcAdmu.log / Write-ToLog so customers send one support log." |
| **`exit` vs `throw` in functions** | `exit` inside library function used by EXE | "Throw so the host can handle errors; reserve `exit` for top-level Invoke contracts." |
| **Readonly registry ignored** | Writable open for read-only FTA/protocol enumeration | "Open the key read-only when we are not writing." |
| **ContainsKey on wrong type** | Assumes hashtable body from API | "Guard types before ContainsKey/indexing; invalid JSON must not continue as success." |

---

## 11. Review Severity Guide

### CRITICAL

Data-loss / lockout / credential exposure on customer devices during migration.

| Example | Why |
|---------|-----|
| ProfileList `.bak` handling destroys the migrated association | User boots into broken/TEMP profile |
| Login block / credential providers disabled without restore | Interactive logon lockout |
| API key or temp password committed or logged | Credential leak |
| MDM removal can delete JumpCloud enrollment | Device management loss |
| Hive rename/copy errors ignored leading to partial migration marked success | Silent corruption |

### WARNING

Wrong migration behavior, bad failure semantics, missing tests on risky paths, GUI/CLI drift.

| Example | Why |
|---------|-----|
| Optional step becomes terminating | Changes field migration success rate |
| NTFS walk aborts on first error | Incomplete ACLs → TEMP profile risk |
| AutoBind GUI allows deselecting LeaveDomain | Unsupported bind state |
| New PS function without tests | Regressions slip past CI |
| SystemContext/AutoBind ordering wrong | Bind fails post leave-domain |
| Native service cleanup missing | Orphaned SYSTEM service |

### NITPICK

Consistency / supportability / release hygiene.

| Example | Why |
|---------|-----|
| Changelog wording / version bump nits | Release clarity |
| Prefer readonly registry open | Handle hygiene |
| Redundant log line / verbose icacls noise | Support log quality |
| Test file in wrong folder | Discoverability |
| Comment/docs drift | Operator confusion |

---

## 12. Files / Areas to Always Scrutinize

| Path | Why |
|------|-----|
| `jumpcloud-ADMU/Powershell/Public/Start-Migration.ps1` | Highest-density migration orchestration |
| `jumpcloud-ADMU/Powershell/Public/Start-Reversion.ps1` | Revert semantics / TEMP / ACL restore |
| `jumpcloud-ADMU/Powershell/Private/Permissions/**` | NTFS ACL performance & safety |
| `jumpcloud-ADMU/Powershell/Private/RegistryKey/**`, `RegistryValidation/**` | Hive/SID/ACL correctness |
| `jumpcloud-ADMU/Powershell/Private/DisplayForms/**` | GUI validation & forced options |
| `jumpcloud-ADMU/Powershell/Private/SystemContext/**`, `JumpCloudFunctions/**`, `Authentication/**`, `JumpCloudApi/**` | API/region/bind |
| `jumpcloud-ADMU/Powershell/Private/SecurityPolicy/**`, `WindowsMDM/**` | Login block & MDM |
| `jumpcloud-ADMU/Powershell/Private/appxPackages/**`, `SystemInfo/Get-UwpJcadmuExe.ps1` | UWP helper |
| `jumpcloud-ADMU-Advanced-Deployment/InvokeFromJCAgent/**` | Remote automation contracts |
| `Deploy/Functions/New-ADMUTemplate.ps1`, `Deploy/uwp_jcadmu.ps1`, `Deploy/Build*.ps1` | EXE surface & helper |
| `ModuleChangelog.md` | Release note discipline |
| `src/JumpCloud.ADMU.Shared/Pipeline/**` | Native phase ordering |
| `src/JumpCloud.ADMU.Shared/Windows/**` | Hive, ACL, MDM, domain, profile services |
| `src/JumpCloud.ADMU.Shared/Security/SecretProtector.cs`, `Models/AdmuJobSecrets.cs` | Secret handling |
| `src/JumpCloud.ADMU.Bootstrapper/**`, `src/JumpCloud.ADMU.Worker/**` | Elevation & SYSTEM service lifecycle |
| `src/JumpCloud.ADMU.Gui/**` | WPF parity with CLI |
| `src/JumpCloud.ADMU.Shared.Tests/**` | Native coverage |
| `.github/workflows/**` | CI label/runner/release safety |

---

## 13. Example Review Output

```json
[
  {
    "file_path": "jumpcloud-ADMU/Powershell/Public/Start-Migration.ps1",
    "line_number": 840,
    "severity": "WARNING",
    "category": "LOGIC",
    "comment": "UWP helper download failures are historically non-breaking. Throwing here turns a recoverable helper gap into a terminating migration failure and changes field behavior.",
    "suggestion": "try {\n    Get-UwpJcadmuExe @uwpParams\n} catch {\n    Write-ToLog -Message \"UWP helper download failed; continuing migration. $($_.Exception.Message)\" -Level Warning -Step \"UWP\"\n}"
  },
  {
    "file_path": "jumpcloud-ADMU/Powershell/Private/Permissions/Set-RegPermission.ps1",
    "line_number": 120,
    "severity": "WARNING",
    "category": "LOGIC",
    "comment": "Throwing on a single ACL item aborts traversal. Reviewers have repeatedly asked that permission walks warn and continue so one bad item cannot leave the rest of the profile under-permissioned.",
    "suggestion": "catch {\n    Write-ToLog -Message \"Skipped '$($item.Path)': $($_.Exception.Message)\" -Level Warning -Step \"Set-RegPermission\"\n    return\n}"
  },
  {
    "file_path": "src/JumpCloud.ADMU.Shared/Windows/MdmRemovalService.cs",
    "line_number": 55,
    "severity": "CRITICAL",
    "category": "SECURITY",
    "comment": "MDM removal must continue to protect JumpCloud enrollments. Dropping that filter can unenroll the device from JumpCloud during migration cleanup.",
    "suggestion": "// Keep JumpCloud enrollment GUIDs out of the removal set before deleting tasks/registry keys.\nif (IsJumpCloudEnrollment(enrollmentGuid)) {\n    CompatibilityLog.Write($\"Skipping JumpCloud MDM enrollment {enrollmentGuid}\");\n    continue;\n}"
  }
]
```

---

## 14. Review Tone

### Do

- Be direct; explain impact on customer migrations, TEMP profiles, logon lockout, and support logs; name exact functions/params.
- Prefer constructor invariants (native) and clear terminating vs non-breaking semantics (PowerShell).

### Do Not

- No LGTM; no generic advice; no comments outside the diff; no echoing bots without verifying.
- Do not recommend method-level null guards for required constructor-injected services.
- Do not modify `.cursor/BUGBOT.md` as part of a normal review unless asked.
- Do not paste machine-local paths into review comments.

---

## Appendix A: Recurring Themes

1. **Migration failure semantics** — what may warn-and-continue vs must fail (UWP, ACL traversal, Invoke exit codes).
2. **Profile hive / registry / `.bak` SID safety** — load/unload/rename, ProfileList, identity after domain leave.
3. **NTFS ACL & long-running permissions** — throw vs continue, reparse skips, FullControl checks, heartbeats, deferred tasks.
4. **GUI ↔ CLI parity** — forced/greyed options, progress init, TEMP-user UX, EXE template param sync.
5. **Secrets & single-log supportability** — no keys/passwords in tests/scripts; prefer `jcAdmu.log`.
6. **Tests** — Pester Acceptance for new PS functions; xUnit for native Shared risks; mock/provider drift.
7. **Release hygiene** — ModuleChangelog deltas, version labels, CI runner caution.
8. **MDM / login policy restore** — JumpCloud enrollment protection; never leave logon blocked after failure.
9. **Native cutover** — service lifecycle, DPAPI secrets, pipeline parity with PowerShell (newer; less PR history).

## Appendix B: Human Reviewer Signals

| Reviewer | Focus |
|----------|-------|
| jworkmanjc | Failure semantics, hive/ACL safety, EXE template/params, changelog discipline, Invoke exit codes, single log, progress heartbeats |
| kmaranionjc | Pester for new functions, GUI validation, Set-JCUrl call-site completeness, TEMP/reversion UX |
| shashisinghjc | UWP/SHA/local EXE validation trade-offs, Start-Reversion TEMP conditions, login policy logging |
| gweinjc | End-to-end migration/reversion validation on VMs, login-block/wallpaper, SetFullPermission behavior |
| slipinjc | Credential-provider / login-policy design (computer-wide backup, redundancy) |
| mmihevcmm | Registry handle hygiene (readonly opens, dispose) |
| edgar-lins | Revert failure gates, SID translation after domain leave, test sequence assertions, culture-independent SIDs |
