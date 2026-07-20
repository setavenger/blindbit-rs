# Linear workspace reference

How to discover workspace-specific conventions at runtime. **Do not assume** team names, repo labels, initiative names, or project names — fetch them from Linear MCP.

## Discover first

| What | Tool | Notes |
|------|------|-------|
| Teams | `list_teams` | Team key (e.g. `ENG`) prefixes issue IDs |
| Issue labels | `list_issue_labels` | Find `repo` parent group and domain labels |
| Initiatives | `list_initiatives` | Top-level containers (engagement / suite / surface) |
| Projects | `list_projects` | Feature projects; often under an initiative |
| Statuses | `list_issue_statuses` | Workflow states per team |
| Documents | `list_documents` | Project-level ADRs and contracts |

Re-sync when labels or teams change. Workspace URL and MCP server name vary by installation — check `GetMcpTools` for the configured Linear server.

## Repo labels

Exactly **one** repo label per issue for code work. Labels typically live under a `repo` parent group.

Discover available repo labels via `list_issue_labels`. The label must match the repo the cloud agent will clone. Match the **Repo scope** table in each issue ([ISSUE-FORMAT.md](./ISSUE-FORMAT.md)).

There is no equivalent label group for `branch` — branch routing goes through an inline `[repo=...] [branch=...]` routing comment. See [SKILL.md § Cursor's resolution order](./SKILL.md#cursors-resolution-order) and [§ Routing comments](./SKILL.md#routing-comments).

## Domain / platform labels

Apply when work spans themes or platforms across projects. Discover via `list_issue_labels` — names vary by workspace. Examples of what teams often use:

| Label type | Typical purpose |
|------------|-----------------|
| `cross-app-platform` | Shared infra consumed by multiple apps |
| Domain-specific (e.g. `notifications`) | Thematic grouping across projects |

## Type labels

| Label | When |
|-------|------|
| `Feature` | New capability |
| `Improvement` | Enhancement |
| `Bug` | Defect |

## Issue statuses

Typical workflow (names may differ per team):

| Status | Type |
|--------|------|
| Backlog | backlog |
| Todo | unstarted |
| In Progress | started |
| In Review | started |
| Done | completed |
| Canceled | canceled |
| Duplicate | duplicate |

Use `list_issue_statuses` for the live list.

## Branch model

Canonical rules: [.agents/reference/git-branch-convention.md](../../../.agents/reference/git-branch-convention.md)

### Two tiers — do not merge milestone issues to main

| Tier | Pattern | Example | Base | PR target |
|------|---------|---------|------|-----------|
| Integration | `{slug}` | `feed-notifications` | `main` | — → `main` at go-live |
| Issue (cloud) | `cursor/{desc}-{hash}` | `cursor/feed-subscription-schema-a1b2` | integration | integration (or stacked parent) |
| Issue (Linear) | `{user}/{team-key}-{num}-{slug}` | `alice/eng-15-feed-subscription-…` | integration | integration |

**Common mistake:** each milestone issue PRs to `main`. Wrong. Stack on integration branch; integration branch → `main` once.

### Integration branch examples

| Project | Repo | Integration branch |
|---------|------|-------------------|
| Notification Platform | `acme/api-service` | `feed-notifications` |
| Notification Platform | `acme/worker` | `feed-notifications` |
| Notification Platform | `acme/web-app` | `feed-notifications` |

Document in Linear project under **Implementation § Git branches**.

### Cloud-agent issue branches (stacked example)

```
cursor/feed-subscription-schema-a1b2
cursor/feed-subscription-api-c3d4          ← stacked on schema branch
cursor/feed-ui-hooks-e5f6                  ← stacked on api branch
```

All PR bases point at integration branch or parent issue branch.

### Refresh workflow

```bash
git checkout feed-notifications && git merge origin/main && git push origin feed-notifications
git checkout cursor/feed-subscription-schema-a1b2 && git merge origin/feed-notifications && git push
```

Merge only. No force-push on published branches.

## Cross-repo pattern (mandatory)

Linear triggers **one repo per issue**. Cross-repo features need three layers:

| Layer | Where | Contains |
|-------|-------|----------|
| Overarching scope | Initiative ([INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md)) | Mission, context, container boundaries |
| Feature why | Project ([PROJECT-FORMAT.md](./PROJECT-FORMAT.md)) | Goal, Reasoning, Effect, rollout, ADR index, status |
| Architecture | Project Linear Document | Context, Decision, Contract, Consequences |
| Issue (per repo) | Linear issue | Goal, Reasoning, Effect, Design (links), Implementation, acceptance criteria |
| Code | Git repo | Implementation matching the shared doc |

Full rules: [CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md) · issue template: [ISSUE-FORMAT.md](./ISSUE-FORMAT.md)

### Workflow

1. `save_document` on project → `ADR-NNNN: {title}` with Contract section.
2. `save_issue` per repo — structured description, one repo label each.
3. Issues link doc in **Design**, ADR § Consequences in **Effect**; list siblings; set `blockedBy`/`blocks` per rollout table.
4. Contract change → update doc only + `save_comment` on affected issues.

### Example (cross-repo split)

Digest dedupe split across repos:

| Issue | Repo label | Links |
|-------|------------|-------|
| ENG-15 | `acme/api-service` | ADR doc + ENG-16 sibling |
| ENG-16 | `acme/worker` | ADR doc + ENG-15 sibling |

API schema lives **only** in the Linear Document — not in either issue body.

## Priority

Linear priority scale: 0 = No priority, 1 = Urgent, 2 = High, 3 = Medium, 4 = Low.

Set explicitly on go-live or deadline-driven projects. Otherwise leave unset.
