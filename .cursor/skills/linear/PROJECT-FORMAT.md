# Project description format

**Every project description must use this structure** when setting up a new feature project or migrating undocumented work into Linear. Agents must not write free-form blurbs. If a section does not apply, write `N/A` — do not omit the heading.

A **project** is a feature or delivery effort under an **initiative** (see [INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md)). Do not use this template for initiative descriptions.

Copy the template below into the project `description` when calling `save_project` (or equivalent update). Fill every section. **Get user confirmation before creating issues** — issues built against an unconfirmed project description need rework.

## Three questions (every project answers these)

| Question | Section(s) | Scope |
|----------|------------|-------|
| **Why** are we building this? | Reasoning | Problem, stakeholders, urgency, alternatives considered |
| **How** are we building it? | Design, Implementation | Design = architecture + ADR index. Implementation = rollout, milestones, repo roles |
| **What effect** will this have? | Effect | Product, system, org impact when the project ships |

## Layering — what belongs where

Don't duplicate content across layers. Initiative orients the container; project sets feature direction; ADRs hold contracts; issues execute.

| Layer | Where | Holds |
|-------|-------|-------|
| Overarching scope | **Initiative** ([INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md)) | Mission, context, what belongs in the container |
| Feature | **Project** (this template) | Why, what ships, connected systems, rollout, status |
| Cross-repo design | **Linear Document** (ADR) | Context, Decision, Contract, Consequences |
| Repo execution | **Issue** ([ISSUE-FORMAT.md](./ISSUE-FORMAT.md)) | Repo-local why, effect, design links, build plan |

Project **Reasoning** = why *this feature* exists — not a repeat of the whole initiative mission.
Project **Design** = architecture overview + ADR links — not full API schemas (those live in ADRs).
Project **Implementation** = rollout order and milestone plan — not per-file touch points (those live in issues).

## Template

```md
## Goal

{One paragraph: what this project delivers when complete. User-visible outcome + technical scope.}

## Reasoning

{Why this feature/project exists. 3–6 sentences: problem, who is affected, why now, what happens if we don't build it. Link the parent initiative for overarching scope.}

- Stakeholders: {teams, users, or N/A}
- Alternatives considered: {what we rejected and why, or N/A}

## Effect

{What changes when this project ships — feature-level impact.}

- Users / product: {who benefits, what they can do, or N/A}
- System / platform: {new capabilities, deprecations, or N/A}
- Operations / support: {monitoring, runbooks, training, or N/A}
- Other projects: {what this unblocks or replaces, or N/A}

## Design

{Architecture at feature/project level — overview, not full contracts.}

### Overview

{2–5 sentences: major components, how repos interact, key integration points.}

### Architecture documents

{Index of Linear Documents on this project. Create ADRs before issues for cross-repo work.}

- [{ADR-NNNN}: {title}]({linear-doc-url}) — {one-line purpose}
- {Add more, or "N/A — single-repo project, no shared contracts yet"}

### Domain concepts

{Ubiquitous language, glossary links, or N/A. Link repo `CONTEXT.md` files or a project Glossary doc.}

## Implementation

{How we deliver the project — not per-issue file lists.}

### Connected systems & repos

| Repo | Role in this project |
|------|----------------------|
| `{org/repo}` | {what this repo owns} |
| {add rows} | |

### Rollout & milestones

{Delivery phases. Use Linear milestones when helpful.}

| Phase / milestone | Delivers | Repos | Notes |
|-------------------|----------|-------|-------|
| {e.g. Data model} | {slice} | api-service | {blocked by nothing} |
| {e.g. Worker} | {slice} | worker | {blocked on phase 1} |

Or N/A for a single-issue project.

### Git branches

{Integration branch per repo — living document, update as branches are created.}

| Repo | Integration branch |
|------|-------------------|
| `{org/repo}` | `{slug}` or `main` |
| {add rows} | |

## Current status

{Where we are today before/during execution.}

- **Done:** {shipped pieces, merged PRs, or "greenfield"}
- **In progress:** {active work, or N/A}
- **Gaps / risks:** {known unknowns, blockers, tech debt}

## Out of scope

{What this project explicitly does NOT include. Point to other projects for adjacent work.}

## Source documents

{Links back to pre-Linear docs, specs, threads, repo markdown. Historical reference only — this project description is canonical for active work.}

- {path or URL}
- {or N/A}
```

## Rules

### Write project before issues

1. Fill this template → present to user for confirmation.
2. Cross-repo? → create Linear Document ADRs ([CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md)) → index them in **Design § Architecture documents**.
3. Only then create issues per [ISSUE-FORMAT.md](./ISSUE-FORMAT.md).

### Design links, doesn't duplicate

| Belongs in ADR | Belongs in project **Design** |
|----------------|-------------------------------|
| API request/response shapes | "Api-service exposes REST; worker consumes events" |
| Event payload schemas | Link ADR-0042 |
| Full data model | One-line summary + ADR link |
| Rollout step details per repo | Milestone table with repo + phase |

### Implementation is rollout, not code

- **Rollout & milestones** = delivery phases and dependencies between them.
- **Git branches** = integration branch table per repo.
- Per-file touch points, handler details → issues only.

### Effect is feature-level

- Good: "Users receive daily digest emails for subscribed feeds; notification center shows unread items."
- Bad: Checkbox acceptance criteria (those belong in issues).
- Bad: Restating the whole parent initiative mission.

### Status stays current

Revisit **Current status** and **Git branches** as work progresses — not a one-time write at project creation.

### Project vs. milestone vs. separate project

| Situation | Use |
|-----------|-----|
| Phase of the same feature (data model → UI → email) | **Milestone** inside this project |
| Reusable infra other features/initiatives will also consume | **Separate project** + `blockedBy` link |
| Single isolated change | Short project or existing project; may skip rollout table |
| New feature under an existing engagement/suite | **Project** under that **initiative** — do not invent a new initiative per feature |

## Labels

Apply domain labels at project level when the feature spans multiple repos. Discover via `list_issue_labels` — names vary by workspace.

Issue-level repo + type labels still apply per [ISSUE-FORMAT.md](./ISSUE-FORMAT.md).

## Example — cross-repo feature

```md
## Goal

Ship notification platform: users subscribe to tagged feeds, receive digest emails, and see notifications in the notification center.

## Reasoning

Users need timely alerts on feed activity without polling. Today there is no subscription model, no digest pipeline, and no in-app notification surface. Competing ask: manual email exports — rejected; doesn't scale and no in-app history.

- Stakeholders: Product team, platform engineers
- Alternatives considered: Real-time push only (rejected — email digest required for audit trail)

## Effect

- Users / product: Subscribe/unsubscribe to feed tags; daily digest email; notification center inbox.
- System / platform: New subscription store, event pipeline, digest worker, frontend notification module.
- Operations / support: Digest failure alerts; subscription audit log.
- Other projects: Unblocks notification-center redesign (separate project, linked via `relatedTo`).

## Design

### Overview

Api-service owns `subscriptions` table and REST API. Worker runs digest pipeline consuming subscription events. Web-app adds subscription UI and notification center panel. Shared contract in ADR-0042.

### Architecture documents

- [ADR-0042: Subscription API]({linear-doc-url}) — REST, data model, events
- [ADR-0043: Digest dedupe strategy]({linear-doc-url}) — idempotency, windowing

### Domain concepts

- **Feed subscription** — user opts into notifications for a feed tag.
- **Digest** — batched email of unread feed events since last send.
- Glossary: link repo `CONTEXT.md` files or project Glossary doc when created.

## Implementation

### Connected systems & repos

| Repo | Role in this project |
|------|----------------------|
| `acme/api-service` | Schema, REST API, event emission |
| `acme/worker` | Digest worker, email rendering, dedupe |
| `acme/web-app` | Subscription UI, notification center |

### Rollout & milestones

| Phase / milestone | Delivers | Repos | Notes |
|-------------------|----------|-------|-------|
| Data model foundations | Table + API + events | api-service | Unblocks worker |
| Digest pipeline | Worker + email | worker | Blocked on foundations |
| Notification UI | Subscribe + inbox | web-app | Can start after API; inbox needs events |

### Git branches

| Repo | Integration branch |
|------|-------------------|
| `acme/api-service` | `feed-notifications` |
| `acme/worker` | `feed-notifications` |
| `acme/web-app` | `feed-notifications` |

## Current status

- **Done:** Greenfield — no prior implementation
- **In progress:** N/A
- **Gaps / risks:** Email template design not finalized; confirm dedupe window with product

## Out of scope

Real-time WebSocket push, mobile app notifications.

## Source documents

- `api-service/docs/notifications-draft.md` (migrated — historical)
- Slack #notifications thread 2026-06-12
```

## Example — small single-repo project

```md
## Goal

Fix invoice line-item edge cases in api-service so empty and partial invoices return correct API responses.

## Reasoning

Production support tickets: 500 errors on invoices with no line items and incorrect totals on partial invoices. Isolated api-service bugfix batch — no cross-repo contract changes.

- Stakeholders: Invoicing users, support team
- Alternatives considered: Frontend workaround (rejected — API should be correct)

## Effect

- Users / product: Invoice detail and list views work for all invoice states.
- System / platform: N/A — behavior fix only.
- Operations / support: Fewer support tickets on invoice 500s.
- Other projects: N/A

## Design

### Overview

Handler fixes in api-service invoice endpoints. No schema changes.

### Architecture documents

N/A — single-repo, no shared contracts.

### Domain concepts

N/A

## Implementation

### Connected systems & repos

| Repo | Role in this project |
|------|----------------------|
| `acme/api-service` | Invoice handler fixes + tests |

### Rollout & milestones

N/A — three small issues, ship directly to `main`.

### Git branches

| Repo | Integration branch |
|------|-------------------|
| `acme/api-service` | `main` |

## Current status

- **Done:** Root cause identified in `handlers/invoice.go`
- **In progress:** N/A
- **Gaps / risks:** N/A

## Out of scope

Frontend display formatting, PDF export.

## Source documents

- Support ticket #4521
```

## Validation before issues

Agent must confirm:

1. All eight sections present (or explicit `N/A` in sub-bullets where noted).
2. **Reasoning**, **Effect**, **Design**, and **Implementation** answer feature/project-level questions — not copy-pasted from a single issue draft, and not a dump of the parent initiative mission.
3. User has confirmed the project description.
4. Cross-repo work → ADRs exist and are indexed in **Design § Architecture documents**.
5. **Git branches** table matches repos in **Connected systems & repos**.
6. Issues will link back here in their **Reasoning → Broader context** bullet.
