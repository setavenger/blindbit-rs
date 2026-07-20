# Issue description format

**Every issue description must use this structure.** Agents must not write free-form blurbs. If a section does not apply, write `N/A` — do not omit the heading.

Copy the template below into `description` when calling `save_issue`. Fill every section before saving.

## Three questions (every issue answers these)

| Question | Section(s) | Scope |
|----------|------------|-------|
| **Why** are we building this? | Reasoning | Repo-local motivation; link project + ADR for feature-level why |
| **How** are we building it? | Design, Implementation | Design = shape/contracts (links). Implementation = repo-local build plan |
| **What effect** will this have? | Effect, Acceptance criteria | Effect = impact when merged. Acceptance criteria = how we verify |

## Layering — what belongs where

Don't duplicate content across layers. Link up, implement down.

| Layer | Where | Holds |
|-------|-------|-------|
| Overarching scope | **Initiative** ([INITIATIVE-FORMAT.md](./INITIATIVE-FORMAT.md)) | Mission, context, what belongs in the container |
| Feature rationale | **Project** ([PROJECT-FORMAT.md](./PROJECT-FORMAT.md)) | Goal, Reasoning, Effect, rollout, status, ADR index |
| Cross-repo design | **Linear Document** (ADR) | Context, Decision, Contract, Consequences |
| Repo execution | **Issue** (this template) | Repo-local why, effect, design links, implementation plan, verification |

Issue **Reasoning** = why *this ticket in this repo now* — not a repeat of the whole project pitch.
Issue **Effect** = what changes *because of this issue's merge* — not a repeat of ADR **Consequences** (link that for cross-repo effects).

## Template

```md
## Goal

{One sentence: what this issue delivers in the primary repo only.}

## Reasoning

{Why this issue exists now — repo-local angle. 2–4 sentences: problem, trigger, urgency.}

- Broader context: {project description section, or ADR § Context link, or N/A for isolated fix}

## Effect

{What changes when this issue merges — repo-local impact.}

- Users / product: {who notices, what improves, or N/A}
- System / data: {schema, API, events, perf, or N/A}
- Cross-repo: {link ADR § Consequences, or N/A}

## Design

{Architectural shape for this repo's slice. Links only — never restate full contract.}

- Shared doc: {Linear document title + link, repo ADR path, or N/A}
- Sibling issues: {ENG-NN, ENG-MM — one per other repo, or N/A}
- Repo-local design notes: {choices that don't belong in shared doc, or N/A}

If no shared architecture doc exists yet for cross-repo work → **create the Linear Document first** (see [CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md)), then reference it here.

## Implementation

{How to build it in this repo.}

### Approach

{Ordered steps or phases — repo-local only.}

### Touch points

{Files, modules, patterns to follow. No API/event/schema duplication — point to Design links.}

## Repo scope

| Field | Value |
|-------|-------|
| Primary repo | `{org/repo}` |
| Repo label | `{exact Linear label from list_issue_labels}` |
| Integration branch | `{slug}` or `main` (single isolated issue) |

## Acceptance criteria

- [ ] {Testable outcome 1 — repo-local}
- [ ] {Testable outcome 2}
- [ ] {Add more as needed}

## Out of scope

{What this issue explicitly does NOT do. Point to sibling issues or the shared doc for the other half.}

## Dependencies

| Relation | Issue | Notes |
|----------|-------|-------|
| Blocked by | {ENG-NN or —} | |
| Blocks | {ENG-NN or —} | |
| Related | {ENG-NN or —} | |

Set the same relations via `blockedBy` / `blocks` / `relatedTo` on `save_issue` — do not rely on the table alone.
```

## Rules

### Repo scope is mandatory

- **Exactly one** repo label from the `repo` parent group for code work.
- Label must match the repo the cloud agent will clone. Discover labels via `list_issue_labels` — see [reference.md](./reference.md).
- If work truly spans repos → split into sibling issues; one label each.

### Design is links-only

| Belongs in shared doc / project | Belongs in issue |
|---------------------------------|------------------|
| API request/response shapes | "Implement endpoint per ADR-0042" |
| Event payload schemas | "Emit event per ADR-0042 § Events" |
| Cross-repo sequencing | Dependency table + `blockedBy` |
| Ubiquitous language / domain terms | Link to `CONTEXT.md` or project glossary doc |
| Integration branch names (project-wide) | This repo's branch name only |
| Feature-level consequences | Link ADR § Consequences in **Effect** |

**Never** paste the same contract into two issues. Two issues → one doc → both link it. A short, explicitly-marked frozen-snapshot excerpt (see [CROSS-REPO-ADR.md](./CROSS-REPO-ADR.md)) is the one exception.

### Reasoning stays repo-local

- Good: "Digest worker can't dedupe until api-service emits `SubscriptionCreated` — blocked on ENG-15."
- Bad: Three paragraphs restating the entire product vision (that belongs in the **project description**).

### Effect describes impact, not verification

- **Effect** = what the world looks like after merge (users, system, siblings).
- **Acceptance criteria** = checkboxes a reviewer can tick. Don't merge the two sections.

### Implementation is actionable

- **Approach** = ordered steps an agent or human can follow.
- **Touch points** = where in the codebase — not a second copy of the API contract.
- Repo-local ADR (`docs/adr/`) → link under **Design** or **Implementation**, not both.

### Acceptance criteria must be verifiable

Each criterion = something a reviewer can check without reading another issue's description. Repo-local behavior only; shared contract verification lives in the ADR or a dedicated contract-test issue.

### Title style

Short imperative phrase scoped to one repo:

- Good: `Subscription table — schema + migration` (api-service)
- Good: `Digest worker — dedupe per ADR-0042` (worker)
- Bad: `Implement notifications` (spans repos, no scope)
- Bad: `Add API and worker` (two repos in one issue)

## Labels checklist

Apply **before** `save_issue`:

| Layer | Required | Pick |
|-------|----------|------|
| Repo | Yes (code work) | Exactly one from `repo` group |
| Type | Yes | `Feature` \| `Improvement` \| `Bug` |
| Domain | When applicable | Discover via `list_issue_labels` |

## Example — api-service half of cross-repo feature

```md
## Goal

Add `subscriptions` table and REST endpoints per shared API contract.

## Reasoning

Frontends need a durable subscription store before the digest worker or notification center can ship. Api-service owns persistence and the public API — this is step 1 in ADR rollout.

- Broader context: [Notification Platform]({project-url}) · [ADR-0042 § Context]({doc-url})

## Effect

- Users / product: N/A until ENG-17 (UI) ships — this issue is backend-only.
- System / data: New `subscriptions` table; `POST`/`DELETE` endpoints live; outbox emits subscription events.
- Cross-repo: Unblocks ENG-16 (worker). See [ADR-0042 § Consequences]({doc-url}).

## Design

- Shared doc: [ADR-0042: Subscription API]({linear-doc-url})
- Sibling issues: ENG-16 (worker digest), ENG-17 (web-app UI)
- Repo-local design notes: N/A — follow existing migration + outbox patterns.

## Implementation

### Approach

1. Migration for `subscriptions` per ADR § Data model.
2. REST handlers per ADR § REST.
3. Outbox emission per ADR § Events.
4. Handler + migration tests.

### Touch points

`db/migrations/`, existing REST handler package, outbox table pattern from prior features.

## Repo scope

| Field | Value |
|-------|-------|
| Primary repo | `acme/api-service` |
| Repo label | `acme/api-service` |
| Integration branch | `feed-notifications` |

## Acceptance criteria

- [ ] Migration creates `subscriptions` per ADR § Data model
- [ ] `POST /subscriptions` and `DELETE /subscriptions/:id` match ADR § REST
- [ ] OpenAPI / handler tests cover happy path and 404

## Out of scope

Digest email rendering, dedupe logic — see ENG-16 and ADR § Events.

## Dependencies

| Relation | Issue | Notes |
|----------|-------|-------|
| Blocked by | — | |
| Blocks | ENG-16 | Worker needs table + events |
| Related | ENG-17 | Notification center UI |
```

## Example — single-repo bug

```md
## Goal

Fix null pointer when invoice has no line items.

## Reasoning

`GET /invoices/:id` panics on invoices with zero line items — reported in production support thread. Isolated api-service fix, no cross-repo impact.

- Broader context: N/A

## Effect

- Users / product: Invoice detail loads for empty invoices instead of 500.
- System / data: Handler returns `lineItems: []` — no schema change.
- Cross-repo: N/A

## Design

- Shared doc: N/A — single-repo fix, no shared contract.
- Sibling issues: N/A
- Repo-local design notes: N/A

## Implementation

### Approach

1. Guard nil/empty slice in invoice handler.
2. Add regression test for empty `lineItems`.

### Touch points

`handlers/invoice.go` (~line 142), existing invoice handler tests.

## Repo scope

| Field | Value |
|-------|-------|
| Primary repo | `acme/api-service` |
| Repo label | `acme/api-service` |
| Integration branch | `main` |

## Acceptance criteria

- [ ] `GET /invoices/:id` returns 200 with empty `lineItems` array
- [ ] Regression test added

## Out of scope

N/A

## Dependencies

| Relation | Issue | Notes |
|----------|-------|-------|
| Blocked by | — | |
| Blocks | — | |
| Related | — | |
```

## Validation before save

Agent must confirm:

1. All nine sections present (or explicit `N/A` in sub-bullets where noted).
2. **Reasoning**, **Effect**, **Design**, and **Implementation** each answer their question — not copy-pasted from project description or ADR.
3. Repo label set and matches **Repo scope** table.
4. Cross-repo work → shared Linear Document exists and is linked in **Design**.
5. No duplicated API/event/schema text that already lives in a sibling issue or shared doc — other than a short, explicitly-marked frozen-snapshot excerpt.
6. `blockedBy` / `blocks` / `relatedTo` match the Dependencies table.
