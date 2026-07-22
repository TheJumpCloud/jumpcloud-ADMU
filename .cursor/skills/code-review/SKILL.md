---
name: code-review
description: >-
  Review jumpcloud-ADMU pull requests and diffs using repo-specific standards
  derived from historical reviews, automated review bots, and Windows AD
  migration / .NET / PowerShell technology best practices. Use when reviewing
  a PR, examining a git diff, running a code review agent, or when the user
  asks for a code review / re-review of jumpcloud-ADMU changes.
---

# Code review (jumpcloud-ADMU)

## Before you start

1. Read [CODE_REVIEW_AGENT_INSTRUCTIONS.md](CODE_REVIEW_AGENT_INSTRUCTIONS.md) in full.
2. Apply existing Cursor project rules if present (read-only unless the user asks to edit):
   - `.cursor/rules/**` (none at skill creation time)
   - `.cursor/BUGBOT.md` (read for reminders if present; do not assume it links here yet)

## How to run a review

Choose a mode, then follow [code-review.prompt.md](code-review.prompt.md) for that mode only:

### A. GitHub PR review (default when a PR number is given)

1. Load PR metadata and diff.
2. Read full files / sibling implementations when the diff is insufficient.
3. Deduplicate against existing human and bot review comments.
4. Apply §9 technology checklists for stacks touched by the diff.
5. Post only net-new findings to the PR using the comment template.
6. Run the multi-model protocol (two passes); posting is allowed in this mode only.

### B. Local / advisory review (branch or working tree, no PR)

When the user asks to review the current branch or working tree **without** a PR number:

1. Diff against `master` (or the requested base) via `git diff` — do not call `gh pr diff` or fetch PR review threads.
2. Apply the same analysis rules and §9 checklists from the instructions.
3. Return the JSON findings array (and a short human-readable summary) **in chat only**.
4. Do **not** call GitHub APIs to post review comments — there is no PR to attach them to.
5. Multi-model Pass 1 and Pass 2 also stay **chat-only** in this mode (never post).

## Usage

> Review PR 279

> Review the current branch diff against master (advisory only — do not post comments)
