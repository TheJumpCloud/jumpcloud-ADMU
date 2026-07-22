# Review Pull Request

Review changes in **jumpcloud-ADMU** using the code review agent instructions.

## Instructions

You are a Principal-level code review agent for **jumpcloud-ADMU**. Follow [CODE_REVIEW_AGENT_INSTRUCTIONS.md](./CODE_REVIEW_AGENT_INSTRUCTIONS.md).

Also apply any in-repo Cursor rules under `.cursor/rules/` and reminders in `.cursor/BUGBOT.md` if present.

## Choose a mode first

| Mode | When | GitHub posting |
|------|------|----------------|
| **A. GitHub PR review** | User gives a PR number | Post line comments on the PR |
| **B. Local / advisory** | Branch or working-tree review, **no** PR number | Return findings in chat only — **never** call GitHub to post |

Follow **only** the workflow for the selected mode. If any other instruction (including multi-model language) says to “post findings,” **Mode B overrides it**: chat only.

---

## Mode A — GitHub PR review

1. **Get PR metadata** — `gh api repos/TheJumpCloud/jumpcloud-ADMU/pulls/{PR}` or GitHub MCP `pull_request_read` with `owner=TheJumpCloud`, `repo=jumpcloud-ADMU`, `pullNumber={PR}`.

2. **Get the diff** — `gh pr diff {PR}` or `git diff {base}...{head}`.

3. **Read full file contents** when the diff is insufficient; compare sibling patterns (`Start-Migration` vs `Start-Reversion`, PowerShell Private helpers vs `src/JumpCloud.ADMU.Shared/Windows/*`, GUI form vs CLI params, Deploy EXE template vs Public params).

4. **Check existing review threads** — do not duplicate human/Bugbot/Cursor/Copilot/CodeRabbit findings on the same root cause.

5. **Analyze** — apply every rule, anti-pattern, and §9 checklist from the instructions (see [Analysis checklist](#analysis-checklist)). Priority: logic → security → reliability → Windows migration domain → tests.

6. **Post findings** — line-level review comments (pending review → comments → submit). Paths repo-relative, no leading `/`. Use the comment template below.

7. **Multi-model** — Pass 1 then Pass 2 per the instructions; Pass 2 only posts net-new findings.

---

## Mode B — Local / advisory review

1. **Do not** fetch PR metadata, review threads, or post comments.

2. **Get the diff** — Against `master` (or the base the user names), e.g. `git diff master...HEAD` or `git diff master` for the working tree. Do **not** use `gh pr diff` unless a PR number was provided (then use Mode A).

3. **Read full file contents** when the diff is insufficient; compare sibling patterns from the working tree / HEAD.

4. **Analyze** — Same analysis as Mode A (see [Analysis checklist](#analysis-checklist)).

5. **Emit findings** — Return the JSON findings array (and a short human-readable summary) **in chat only**.

6. **Multi-model** — Pass 1 then Pass 2 per the instructions; Pass 2 only reports net-new findings **in chat**. Never post to GitHub. Ignore any “post findings” wording for this mode.

---

## Analysis checklist

Apply every rule, anti-pattern, and technology-specific check from `CODE_REVIEW_AGENT_INSTRUCTIONS.md`.

- Identify which technologies the diff touches (PowerShell module, Pester, Deploy/PS2EXE, Advanced-Deployment Invoke, WinForms/WPF GUI, .NET 8 Shared/Bootstrapper/Worker, Windows registry/hives/ACL, JumpCloud API/System Context, MDM/domain leave, UWP helper, CI workflows).
- Run the matching checklists in **§9 Technology Inventory & Best-Practice Checks** (including the §9.0 quick checklist).
- Focus on (priority order):
  - Logic — terminating vs non-breaking failures, phase ordering, SID/`.bak` registry safety
  - Security — API keys, connect keys, temp passwords, DPAPI secrets, privilege/SYSTEM paths, MDM JumpCloud enrollment protection
  - Reliability — hive load/unload, NTFS traversal, service install/cleanup, progress heartbeats
  - Domain — AD/Entra → local migration, reversion, AutoBind/SystemContext, leave-domain sequencing
  - Tests / release hygiene — Pester/xUnit coverage, ModuleChangelog delta, EXE template param sync

## Comment Template (Mode A only)

```
**{SEVERITY} — {CATEGORY}**: {comment}

**Suggestion**:
```powershell
{suggestion code}
```

_Comment created by JC-ReviewAgent_
```

For C# diffs, use a `csharp` fence instead of `powershell`.

## Rules

- Only comment on diff lines.
- Suggestions must be compilable / clearly integrable (PowerShell or C#).
- One comment per root cause.
- If clean: Mode A posts nothing; Mode B returns `[]`.
- Be specific — no vague warnings.

## Re-review (Mode A only)

1. Fetch existing threads.
2. Filter prior `JC-ReviewAgent` comments.
3. Avoid duplicates with other reviewers.
4. Re-fetch latest diff.
5. Resolve or reactivate with `Re-activated —`.
6. Post only new findings.
7. Summarize.

## Usage

**Mode A — GitHub PR review** (posts comments):

> Review PR 279

**Mode B — Local / advisory** (no post):

> Review the current branch diff against master (advisory only)
