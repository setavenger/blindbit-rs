---
name: linear
description: Manage Linear initiatives, projects, issues, and workflows. Use when creating or updating Linear initiatives/projects/issues, triaging work, routing tasks to repos, choosing labels, writing structured initiative/project/issue descriptions, creating cross-repo Linear Document ADRs, naming git branches, setting up a brand-new Linear project for a previously-undocumented feature, or coordinating cloud agents against Linear tickets.
---

# Linear

Workflow for [Linear](https://linear.app). Use the configured Linear MCP server for reads and writes — discover tools via `GetMcpTools`.

## Teams

Discover teams via `list_teams`. Each team has a key (e.g. `ENG`) that prefixes issue IDs (e.g. `ENG-15`).

If the user has not specified a team, ask or infer from project context. Do not assume team names or keys.

## Hierarchy

```
Initiative → Project → Milestone (optional) → Issue
```

Teams still own issues (IDs like `ENG-15`). Initiatives and projects organize work above that.

- **Initiative** = top-level container for an overarching scope (customer engagement, product suite, long-lived surface). Projects roll in over time — not a closed checklist. See [INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md).
- **Project** = feature or delivery effort inside an initiative (e.g. "Harvest log export", "Subscription digests").
- **Milestone** = delivery slice inside a project (e.g. "Data model foundations", "Digest email").
- **Issue** = one unit of work with a single primary repo.

Every issue should have a **project**. Attach projects to an **initiative** when the work belongs to an existing scope. Add a **milestone** when the project uses them. Do not nest initiatives unless the user explicitly asks.

## Initiative setup

When work belongs to a customer engagement, product suite, or other long-lived scope:

1. **Find or create the initiative** (`list_initiatives` / `save_initiative`). Description follows [INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md) — mission and context, not the project Goal/Reasoning scaffold.
2. **Do not** require a complete project list up front. Initiatives collect projects as features are requested or discovered.
3. **Do not** overwrite a rich initiative description with a one-line stub. If cleaning up a mega-project into an initiative, preserve substance; tighten structure, don't empty it.
4. Flat initiatives only unless the user asks for nesting.

## Project setup (new / previously-undocumented feature)

Before creating a single issue for a large feature that has never lived in Linear (e.g. migrating scattered markdown docs into a real project):

1. **Confirm the parent initiative** when one exists (or create it first per above). The project is the feature; the initiative is the container.
2. **Write the project description first** using the fixed template in [PROJECT-FORMAT.md](./PROJECT-FORMAT.md). Eight sections: Goal · Reasoning · Effect · Design · Implementation · Current status · Out of scope · Source documents (with sub-sections per template). Get it reviewed/confirmed by the user before creating any issues — issues built against an unconfirmed description need rework. Issues carry repo-local **Reasoning** and **Effect**; the project holds feature-level why, effect, and rollout.
3. **Only then create issues** per [ISSUE-FORMAT.md](./ISSUE-FORMAT.md). Don't rush to issue creation to "make progress" — issues are cheap to fix, but a wrong-scoped batch of them is not.
4. **Project vs. milestone** — decide per sub-piece:
   - Standalone, reusable infrastructure that other work also consumes — even if you only discovered it as a dependency of this feature — gets its own **project**, not a milestone. Link the two projects with an issue-level `blockedBy` relation; don't nest one inside the other.
   - A themed phase or slice of the *same* feature (e.g. "data model" vs. "UI" vs. "email delivery"; "ships now, no dependency" vs. "blocked on X") is a **milestone** inside the same project.
5. **Prefer granular issues over a few big ones** once the project/milestone structure exists. Split a vague "fix the whole workflow" bucket into one issue per concrete, independently-shippable change. Linear's relations, milestones, and labels are built to handle many small issues cheaply — a wall-of-text single issue is not more efficient, it's just less visible.

## Issue workflow (status)

Use these statuses in order:

1. **Backlog** — defined, not scheduled
2. **Todo** — ready to pick up
3. **In Progress** — actively being worked
4. **In Review** — PR open or awaiting review
5. **Done** — merged / shipped

Also available: **Canceled**, **Duplicate**. Do not leave issues in limbo between In Progress and In Review when a PR exists.

Use `list_issue_statuses` for the live list — names may differ per team.

## Labels

Apply **all** labels that fit. Discover labels via `list_issue_labels` — do not hardcode workspace-specific names.

### Cursor's resolution order

Cursor resolves an issue's target **repo + branch** in this priority order:

1. Inline `[repo=owner/repo] [branch=branch-name]` tags (in the issue description or a comment)
2. Issue-level label
3. Project-level label
4. Cursor Dashboard default

There is no label-group mechanism for `branch` (only `repo` has one — see below), so branch routing always goes through the inline tag. See [Routing comments](#routing-comments).

### 1. Repo label (required for code work)

Parent group: `repo`. Pick exactly one primary repo label. Discover available labels via `list_issue_labels`.

Cloud agents: resolve label → repo, then follow branch rules in [.agents/reference/git-branch-convention.md](../../../.agents/reference/git-branch-convention.md).

### 2. Domain / platform label (when applicable)

Apply domain labels when work is thematically related across projects. Names vary by workspace — discover via `list_issue_labels`.

Apply the same domain label across **multiple projects** when work is thematically related but intentionally split into separate projects — this gives cross-project findability without forcing unrelated scopes into one project.

### 3. Type label (pick one)

| Label | When |
|-------|------|
| `Feature` | New capability |
| `Improvement` | Enhancement to existing behavior |
| `Bug` | Defect fix |

### Gotchas

- An issue's `labels` field on `save_issue` is a **full-set replace**, not additive. Always pass the union of existing + new labels, or you will silently wipe existing ones.
- A **project's** `labels` field is a completely different namespace from an **issue's** `labels` field. Issue-label names do not resolve as project labels — don't try to reuse them there.

## Routing comments

The `repo` label group covers human-facing filtering in Linear, but there's no equivalent label-group mechanism for `branch`. Route the branch with an inline **comment** instead of baking it into the description — keeps the substantive description clean:

```
**Routing:** `[repo=acme/api-service] [branch=feed-notifications]`
```

Post it via `save_comment`, not inside `description`. If the target branch changes later, delete the old routing comment and post a corrected one — a one-comment fix instead of an issue-description diff.

## Single-repo rule

**One issue → one primary repo.** Linear cloud agents trigger one repo per issue — design for that.

If work spans repos (e.g. api-service + worker):

1. Create a **project-level Linear Document** for the shared contract/ADR — see [CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md).
2. Split into **sibling issues** — one per repo, one repo label each.
3. Each issue links the shared doc; **never** duplicate API/event/schema text across issues.

Do not assign multiple repo labels to a single issue. Prefer split issues + shared doc.

## Git branches — two tiers

Large features use **two branch levels**. Do not merge project/milestone issues straight to `main`.

Full rules: [.agents/reference/git-branch-convention.md](../../../.agents/reference/git-branch-convention.md)

```
main
  └── {integration-slug}              ← per-repo integration branch (e.g. feed-notifications)
        └── cursor/{desc}-{hash}      ← issue branch (cloud agents)
```

### Integration branch (required for large work)

Every **project** or **milestone** spanning multiple issues needs an **integration branch per repo** before issue work starts.

| Concept | Pattern | Example | Merges into |
|---------|---------|---------|-------------|
| **Integration branch** | bare `{slug}` — no `feature/` prefix | `feed-notifications`, `billing-v2` | `main` once at go-live |
| **Issue branch (cloud agent)** | `cursor/{kebab-desc}-{4hex}` | `cursor/feed-subscription-schema-a1b2` | integration branch |
| **Issue branch (Linear UI)** | `{user}/{team-key}-{num}-{slug}` | `alice/eng-15-feed-subscription-…` | integration branch |

**Cloud agents must use `cursor/` branches** and must not target `main` for project/milestone work.

Record integration branch names in the project description **Implementation § Git branches** table ([PROJECT-FORMAT.md](./PROJECT-FORMAT.md)). When a project spans repos, each repo gets its own integration branch (same slug is fine). Treat this table as a **living document** — revisit and correct it as branches are created or fixed, not a one-time write.

### Introducing an integration branch retroactively

If an integration branch gets introduced after some issues already have open PRs targeting `main`: **retarget those PRs' base branch** to the new integration branch — don't leave them pointed at `main`, and don't re-create them.

If one repo in a multi-repo feature already has the integration branch and a sibling repo doesn't, create the missing one explicitly (branch off that repo's current `main`, push) — don't let the inconsistency slide.

### Unrelated bugfixes stay on main

A bugfix found while working the feature but not actually part of its scope still targets `main` directly. Don't sweep every discovered fix into the feature's integration branch just because it surfaced during the same planning session.

### Issue branches

**Cloud agents:**

```
cursor/{kebab-description}-{4hex}
```

**Humans / Linear default** (`gitBranchName` on issue):

```
{github-username}/{team-key-lowercase}-{issue-number}-{slug}
```

Rules (both formats):

- **Base branch = integration branch**, not `main`.
- **PR target = integration branch** by default — never `main` for project/milestone issues.
- **Stacked PRs:** when issue B depends on A, base PR on A's issue branch; merge in dependency order.
- One branch per issue; one logical change per commit.
- **No force-push** / **no rebase** of published branches without explicit instruction.

### When to skip an integration branch

Single isolated issue, no coordinating milestone → branch from `main`, merge to `main`. If unsure, use an integration branch.

### Keeping integration branches current

Merge `main` **into** the integration branch (not the reverse):

```bash
git checkout feed-notifications && git merge origin/main && git push origin feed-notifications
git checkout cursor/feed-subscription-schema-a1b2 && git merge origin/feed-notifications && git push
```

Use merge when open PRs exist — not rebase + force-push.

### Main merge (go-live only)

Integration branch → `main` **once** when the project ships. Issue Done = merged into integration branch, not production.

## Issue description (required structure)

**Every issue description must follow the fixed template** in [ISSUE-FORMAT.md](./ISSUE-FORMAT.md). No free-form blurbs.

Nine sections, always: Goal · Reasoning · Effect · Design · Implementation · Repo scope · Acceptance criteria · Out of scope · Dependencies.

Each issue answers **why** (Reasoning), **how** (Design + Implementation), and **what effect** (Effect). Cross-repo contracts live in a **Linear Document on the project**, not in issue bodies — issues link the doc in **Design**.

## Creating initiatives

1. Confirm whether an initiative already exists (`list_initiatives`) before creating another for the same scope.
2. Fill description from [INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md) — mission/context; not the project template.
3. Set `summary` to a one-line orientation; put real substance in `description`.
4. Attach new feature **projects** to this initiative as they appear — no need to pre-create the full set.

## Creating projects

Before creating issues on a new feature project:

1. Confirm **team** via `list_teams` or user input.
2. Confirm **initiative** when the work belongs to an existing scope (`list_initiatives` / `get_initiative`). Attach via `save_project` `addInitiatives` / `setInitiatives`.
3. Fill project description from [PROJECT-FORMAT.md](./PROJECT-FORMAT.md) — validate all sections and three questions (why / how / effect).
4. **User confirmation required** before creating any issues.
5. Cross-repo? → `save_document` ADRs on project first → index in **Design § Architecture documents**.
6. Set domain labels on project when applicable.

## Creating issues

Before `save_issue`:

1. Confirm **team** and **project** (`list_projects` / `get_project`). Project description must follow [PROJECT-FORMAT.md](./PROJECT-FORMAT.md).
2. **Cross-repo?** → `save_document` on the project first ([CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md)), then create per-repo issues that link it.
3. Set **repo label** — exactly one from `repo` group; must match Repo scope table in description.
4. Fill description from [ISSUE-FORMAT.md](./ISSUE-FORMAT.md) template — validate all nine sections and the three questions (why / how / effect).
5. Set `blockedBy` / `blocks` / `relatedTo` to match Dependencies table.
6. Assign **milestone** when the project has active milestones.
7. Set **priority** only when user or project lead specifies; otherwise leave unset.
8. Multi-issue project → project description follows [PROJECT-FORMAT.md](./PROJECT-FORMAT.md) (integration branches + ADR index).

Title: short imperative, single-repo scope — "Subscription table — schema + migration", not "Implement notifications".

## Same-file / same-view collisions

Issues in the same milestone are not independent just because there's no cross-repo dependency between them. Before finalizing a batch of issues, explicitly check whether multiple issues touch the same file or the same UI view — read the actual files, don't guess from titles.

When they do:

- Add a structured relation: `blockedBy` if there's a genuine implementation-order dependency, `relatedTo` otherwise.
- Add a plainly visible note in each affected issue's description, e.g. "Shares `Foo.tsx` with: ENG-12, ENG-14 — no hard block, but expect to rebase." People and agents often only read the title or skim the description and won't proactively open the relations tab.

This risk is not hypothetical once issues route to independently-triggered cloud agents that may run concurrently on the same base branch.

## Verify before you write

- Check the actual current codebase (grep/read real files) before writing or trusting an issue's technical claims — don't rely on assumed names or remembered structure.
- Once issues exist with a `delegate: Cursor` field visible, assume real agents may already be working the backlog concurrently with your planning. Check an issue's current status and any linked PR before editing its description or relations — don't clobber in-flight work or leave stale guidance.
- Always `git fetch` before trusting a local branch ref to check merge status — a stale local ref can make already-merged work look unmerged, or vice versa.

## Cloud agents + Linear

When a cloud agent works a ticket:

1. Read issue via `get_issue` (ID like `ENG-15`).
2. Read **Reasoning** → **Design** → **Implementation** → **Effect**. Fetch linked Linear Document via `get_document` (from **Design**) or repo ADR. Implement against shared docs — not against sibling issue text.
3. Read the **project** description ([PROJECT-FORMAT.md](./PROJECT-FORMAT.md)) → **Implementation § Git branches** for this repo's integration branch; **Reasoning** / **Effect** for feature context. Skim the parent **initiative** ([INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md)) for overarching scope when present.
4. Check repo label → clone/checkout the matching repo.
5. Checkout the **integration branch** (create from `main` if missing and project is multi-issue).
6. Create issue branch from integration branch: `cursor/{desc}-{4hex}` (cloud agents). Include Linear issue key in commit/PR body even if not in branch name.
7. Open PR with **base = integration branch** (or parent issue branch if stacked) — never `main` for project/milestone issues.
8. Move status to **In Progress** when starting; **In Review** when PR is ready.
9. Comment on issue with PR link, base branch, and summary (`save_comment`).
10. Mark **Done** when PR merges into integration branch — not when merged to `main`.

If integration branch undocumented on multi-issue project/milestone → **stop and ask**. No silent `main` default.

Cursor may appear as **delegate** on issues — that is expected for agent-driven work.

## Subagents for Linear-heavy planning

When planning spans many files/repos and produces many Linear writes:

- Run a **read-only research subagent first** to synthesize sprawling existing documentation into one structured summary before writing anything into Linear.
- Once you've decided exactly what to write, **delegate the mechanical Linear API calls** to fast/cheap subagents. Don't spend an expensive model's context on repetitive tool calls.
- **Batch mechanical work into parallel subagent calls** grouped by a natural partition (e.g. one subagent per repo+branch combination).
- Run a **dedicated read-only verification subagent** at the end of a batch of Linear writes to catch mistakes before declaring the work done.
- **Gotcha:** a subagent launched fully read-only loses MCP tool access *entirely*. If a subagent needs any MCP tool — even read-only — don't mark it fully read-only; instruct it explicitly to only call specific read-only tool names.

See also [subagent-orchestration](../subagent-orchestration/SKILL.md) for general delegation patterns.

## MCP quick reference

| Task | Tool |
|------|------|
| List/filter issues | `list_issues` |
| Get one issue | `get_issue` |
| Create/update issue | `save_issue` |
| Comment | `save_comment` |
| Initiatives | `list_initiatives`, `get_initiative`, `save_initiative` |
| Projects | `list_projects`, `get_project`, `save_project` |
| Shared ADRs / contracts | `list_documents`, `get_document`, `save_document` |
| Labels | `list_issue_labels`, `list_initiative_labels` |
| Statuses | `list_issue_statuses` |
| Teams | `list_teams` |

Always call `GetMcpTools` before first MCP use in a session.

## More detail

- **Initiative template:** [INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md)
- **Project template (mandatory):** [PROJECT-FORMAT.md](./PROJECT-FORMAT.md)
- **Issue template (mandatory):** [ISSUE-FORMAT.md](./ISSUE-FORMAT.md)
- **Cross-repo ADRs / contracts:** [CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md)
- Workspace discovery guide: [reference.md](reference.md)
- Git branch naming: [.agents/reference/git-branch-convention.md](../../../.agents/reference/git-branch-convention.md)
- Repo-local domain language: [domain-modeling](../domain-modeling/SKILL.md)
